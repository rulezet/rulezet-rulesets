rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ed248bd8fbbe3015d7c51a02ff82fb953435e29279a89532e416b6c33d05a59"

  strings:
    $s1  = "&DiscordBot.Modules.Commands+<Help>d__0" fullword ascii
    $s2  = "dg3ypDAonQcOidMs0w.WP6RZJql8gZrNhVA9v+RJDcsuMfOxrTCYImPe+iGR41459RDH4FvPdNk`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii
    $s3  = "<Embed>5__10" fullword ascii
    $s4  = "<Embed>5__2" fullword ascii
    $s5  = "<Help>d__0" fullword ascii
    $s6  = "<Embed>5__3" fullword ascii
    $s7  = "<Embed>5__1" fullword ascii
    $s8  = "<Embed>5__6" fullword ascii
    $s9  = "<Module>{2D52E9C6-7CB3-4302-934D-0CB1374DF6DF}" fullword ascii
    $s10 = "<Stealth>5__6" fullword ascii
    $s11 = "g[*H[LiKE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}