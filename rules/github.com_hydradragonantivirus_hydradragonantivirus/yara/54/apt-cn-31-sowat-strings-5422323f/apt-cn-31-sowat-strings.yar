rule apt_CN_31_sowat_strings {
  meta:
    author      = "@imp0rtp3"
    description = "Apt31 router implant (SoWaT) strings"
    reference   = "https://imp0rtp3.wordpress.com/2021/11/25/sowat/"

  strings:
    $a1 = "exc_cmd time out" fullword
    $a2 = "exc_cmd pipe err" fullword
    $a3 = "./swt  del" fullword
    $a4 = "mv -f %s %s ;chmod 777 %s " fullword
    $a5 = "./%s  port  %d " fullword
    $a6 = "./%s  del  %d " fullword

        $a7 = "Usage : ntpclient destination\n" fullword
    $a8 = "killedd" fullword

        $a9 = { 53 14 3d 23 94 78 a9 68 2f 68 c9 a2 1a 93 3c 5b 39 52 2d 1d e0 63 59 1c 30 44 a2 6a 2a 3f a2 95 }

    $b1 = "nameserver" fullword
    $b2 = "conf" fullword
    $b3 = "swt" fullword
    $b4 = "192.168." fullword
    $b5 = "rm %s " fullword
    $b6 = "ipecho.net" fullword
    $b7 = "Host: ipecho.net\x0d\x0a"
    $b8 = "send errno: %d\x0a" fullword
    $b9 = "exit 0" fullword

        $b10 = "ctrl-c" fullword
    $b11 = "malloc err" fullword

  condition:
    uint32(0) == 0x464c457f and
    filesize < 2MB and
    (
      9 of ($b*) or
      3 of ($a*) or
      (
        6 of ($b*) and
        any of ($a*)
      ) or (
        3 of ($b*) and
        2 of ($a*)
      )
    )
}