rule mal_iwebservices {
  meta:
    description = "Identify the iWebServices malware"
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.02.19"
    reference   = "https://objective-see.org/blog/blog_0x72.html"
    sample      = "3e66e664b05b695b0b018d3539412e6643d036c6d1000e03b399986252bddbfb"
    DaysofYARA  = "50/100"

  strings:
    $s1 = "/update.php"
    $s2 = "/install.php"
    $s3 = "/tmp/iwup.tmp"

    $c1 = {
      e8 [4]                49 89 c4              45 31 ed              4d 85 e4              74 ??                 4c 89 e0              49 ff c4              c6 00 00              be 3b 00 00 00        4c 89 e7              e8 [4]                48 89 c3              45 31 ed              48 85 db              74 ??                 48 89 d8              48 ff c3              c6 00 00              be 3b 00 00 00        48 89 df              e8 [4]                45 31 ed              48 85 c0              74 ??               }

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    all of ($s*) or
    all of ($c*)
}