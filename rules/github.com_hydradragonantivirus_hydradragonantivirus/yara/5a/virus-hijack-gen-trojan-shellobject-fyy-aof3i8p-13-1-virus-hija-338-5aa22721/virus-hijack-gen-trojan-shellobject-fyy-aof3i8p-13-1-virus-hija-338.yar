import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_fyY_aOF3i8p_13_1_Virus_Hija_338 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.fyY@aOF3i8p_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2108dfb3889c739424c76cfab89967b106303bbb48527797663968a5fad0c9c"
    hash2       = "91108d07454bd8e212cc115ef1211832c7fcadce9bb9fbae1000811f0ccaad7b"

  strings:
    $s1  = "\\pard\\keepn\\fi-360\\li720\\sb120\\sa120\\tx720\\lang1036\\'b7\\tab tout  ce qui est reli\\'e9 au logiciel, aux services ou au" ascii
    $s2  = "could not read resource data entry fr" fullword ascii
    $s3  = "ou must comply with all domestic a" fullword ascii
    $s4  = " compris le code) figurant sur des sites Internet " fullword ascii
    $s5  = "These license terms are an agreement between Sysinternals(a wholly owned subsidiary of Microsoft Corporation) and y" fullword wide
    $s6  = "bec, Canada, certaines des clauses dans ce contrat sont fo" fullword wide
    $s7  = "`placement delete " fullword ascii
    $s8  = " acquired the software.  This agreement does not change your rights " fullword ascii
    $s9  = "ts.  You may have other rights under the law" fullword ascii
    $s10 = "*make more copies of the softwa" fullword wide
    $s11 = "The software is licensed, not sold.This agreement only gives you some rights to use the " fullword wide
    $s12 = "Would you lik" fullword wide
    $s13 = "It also applies even if Sysinternals knew or should have known about the possibility of the damages.The above limitation or excl" wide
    $s14 = "*reverse engineer, decompile or disassemble the software, except and only to the extent that applicable law expressly permits, d" wide
    $s15 = "\\caps\\fs20 6.\\tab\\fs19 Export Restrictions\\caps0 .\\b0   The software is subject to United States export laws and regulatio" ascii
    $s16 = "You can recover from sysintern" fullword wide
    $s17 = "You can recover from sysinternals" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f1a539a5b71ad53ac586f053145f08ec" and (8 of them)
    ) or (all of them)
}