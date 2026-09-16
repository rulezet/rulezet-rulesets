import "pe"
rule _Trojan_Hooker_Win32_Floxif_A_15_Virus_Hijack_Gen_Trojan_ShellOb_164 {
  meta:
    description = "datamaliciousorder - from files Trojan.Hooker_Win32.Floxif.A_15.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@a853Pwn_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "038a0f760ba5b33aafd0cbabc777eb7124d5479e12cbbbd5b16f7618bdd7f7a2"
    hash2       = "9707460e47c7f7cd585f39e7a34de079bc86f7fe792e9481c845acc1f3052acb"

  strings:
    $s1  = "SELECT hostname, encryptedUsername, encryptedPassword, encType FROM moz_logins" fullword ascii
    $s2  = "{Execute}" fullword ascii
    $s3  = "%s: %s and %s are the same file" fullword ascii
    $s4  = "%s: %s: cannot %scompress onto itself" fullword ascii
    $s5  = "Cannot get standard input/output handles" fullword ascii
    $s6  = "{Return}" fullword ascii
    $s7  = "{Select}" fullword ascii
    $s8  = "{Backspace}" fullword ascii
    $s9  = "HOLD;%s" fullword ascii
    $s10 = "{Insert}" fullword ascii
    $s11 = "{Delete}" fullword ascii
    $s12 = "{Snapshot}" fullword ascii
    $s13 = "{Separator}" fullword ascii
    $s14 = "Received channel request for nonexistent channel %d" fullword ascii
    $s15 = "RegK not written" fullword ascii
    $s16 = "{Down}" fullword ascii
    $s17 = "{Left}" fullword ascii
    $s18 = "{Clear}" fullword ascii
    $s19 = "{Right}" fullword ascii
    $s20 = "{Print}" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "23b7a2ad6dd5722f5566eaa0d8a348bf" and (8 of them)
    ) or (all of them)
}