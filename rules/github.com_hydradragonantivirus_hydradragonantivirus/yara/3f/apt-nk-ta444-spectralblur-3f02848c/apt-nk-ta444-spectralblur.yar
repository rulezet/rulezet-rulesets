rule APT_NK_TA444_SpectralBlur {
  meta:
    author      = "Greg Lesnewich"
    description = "track the SpectralBlur backdoor"
    date        = "2023-08-21"
    version     = "1.0"
    hash        = "6f3e849ee0fe7a6453bd0408f0537fa894b17fc55bc9d1729ae035596f5c9220"
    DaysofYARA  = "3/100"

  strings:
    $xcrypt1 = {
      99                    f7 [4-8]              8b [4-8]              48 63 d2              0f b6 0c 11           01 c8                 b9 00 01 00 00        99                    f7 f9               }

    $xcrypt2 = {
      8b 85 c4 fe ff ff        83 c0 01                 b9 00 01 00 00           99                       f7 f9                    [20-40]
      01 c8                    b9 00 01 00 00           99                       f7 f9                  }

    $symbol1  = "xcrypt" ascii wide
    $symbol2  = "_proc_die" ascii wide
    $symbol3  = "_proc_dir" ascii wide
    $symbol4  = "_proc_download" ascii wide
    $symbol5  = "_proc_download_content" ascii wide
    $symbol6  = "_proc_getcfg" ascii wide
    $symbol7  = "_proc_hibernate" ascii wide
    $symbol8  = "_proc_none" ascii wide
    $symbol9  = "_proc_restart" ascii wide
    $symbol10 = "_proc_rmfile" ascii wide
    $symbol11 = "_proc_setcfg" ascii wide
    $symbol12 = "_proc_shell" ascii wide
    $symbol13 = "_proc_sleep" ascii wide
    $symbol14 = "_proc_stop" ascii wide
    $symbol15 = "_proc_testconn" ascii wide
    $symbol16 = "_proc_upload" ascii wide
    $symbol17 = "_proc_upload_content" ascii wide
    $symbol18 = "_sigchild" ascii wide

    $string1 = "/dev/null" ascii wide
    $string2 = "SHELL" ascii wide
    $string3 = "/bin/sh" ascii wide
    $string4 = "%s \n%s \n%s \n%s \n%s \n%s \n%s \n%s "  
  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    (any of ($xcrypt*) or 4 of ($symbol*) or (all of ($string*)))
}