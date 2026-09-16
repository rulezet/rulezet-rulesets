rule Virus_Hijack_Gen_Trojan_ShellObject_RAZ_aCEmdoo_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.RAZ@aCEmdoo_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61108c60c3a483c21f5aaa85679a721fc5086c4253b5bded687bfb8efef06072"

  strings:
    $s1 = "level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsof" ascii
    $s2 = "A build of the Lacey portable" fullword wide
    $s3 = ":compatibility.v1\"><application><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/><supportedOS Id=\"{e2011457-1546-43" ascii
    $s4 = "sz development" fullword wide
    $s5 = "Copyright sz development" fullword wide
    $s6 = "the sz development Lacey" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}