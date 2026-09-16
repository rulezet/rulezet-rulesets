import "pe"
rule CrunchPE_ren: Packer PEiD {
  meta:
    author = "malware-lu"
    note   = "Added extra checks"

  strings:
    $a0 = { 55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 }
    $b  = { EB 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 5D 81 ED 18 ?? ?? ?? 8B C5 55 60 9C 2B 85 E9 06 ?? ?? 89 85 E1 06 ?? ?? FF 74 24 2C E8 BB 01 00 00 0F 82 92 05 00 00 E8 F1 03 00 00 49 0F 88 86 05 00 00 68 6C D9 B2 96 33 C0 50 E8 24 03 00 00 89 85 D9 41 00 00 68 EC 49 7B 79 33 C0 50 E8 11 03 00 00 89 85 D1 41 00 00 E8 67 05 00 00 E9 56 05 00 00 51 52 53 33 C9 49 8B D1 33 C0 33 DB AC 32 C1 8A CD 8A EA 8A D6 B6 08 66 D1 EB 66 D1 D8 73 09 66 35 20 83 66 81 F3 B8 ED FE CE 75 EB 33 C8 33 D3 4F 75 D5 F7 D2 F7 D1 5B 8B C2 C1 C0 10 66 8B C1 5A 59 C3 68 03 02 00 00 E8 80 04 00 00 0F 82 A8 02 00 00 96 8B 44 24 04 0F C8 8B D0 25 0F 0F 0F 0F 33 D0 C1 C0 08 0B C2 8B D0 25 33 33 33 33 33 D0 C1 C0 04 0B C2 8B D0 25 55 55 55 55 33 D0 C1 C0 02 0B C2 }

  condition:
    for any of ($*): ($ at pe.entry_point)
}