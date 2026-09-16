rule Virus_Hijack_Trojan_GenericKDZ_105924_186_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_186_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b29c7289d14ae92afa2242d7fb416021f89eadd2e87271960483137a5732756"

  strings:
    $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><noInherit></noInherit><assemblyIdentity processorA" ascii
    $s2 = "tecture=\"x86\" type=\"win32\" name=\"xev\" version=\"1.0.0.0\"></assemblyIdentity><description>xev</description><dependency><de" ascii
    $s3 = "\"Target" fullword ascii
    $s4 = "if defined _OLD_VIRTUAL_PROMPT (" fullword ascii
    $s5 = "if defined _OLD_VIRTUAL_PYTHONHOME (" fullword ascii
    $s6 = "if defined _OLD_VIRTUAL_PATH (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}