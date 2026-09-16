rule VirusShareTrojanMulDropNET40 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanMulDropNET40.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be6cfe2d0cad2a1a5acad67136be90a8a2464d3bb6b285bccce4ff8ea175643b"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "+(c) 2011-2019 Henry++. All Rights Reversed." fullword ascii
    $s3 = "(c) 2011-2019 Henry++. All Rights Reversed." fullword wide
    $s4 = "Mem Reduct" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}