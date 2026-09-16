import "pe"
rule PEiD_00280_AZProtect_0001___by_AlexZ_aka_AZCRC_ {
  meta:
    description = "[AZProtect 0001 - by AlexZ aka AZCRC]"
    ep_only     = "true"

  strings:
    $a = { FC 33 C9 49 8B D1 33 C0 33 DB AC 32 C1 8A CD 8A EA 8A D6 B6 08 66 D1 EB 66 D1 D8 73 09 66 35 20 83 66 81 F3 B8 ED FE CE 75 EB 33 C8 33 D3 4F 75 D5 F7 D2 F7 D1 8B C2 C1 C0 10 66 8B C1 C3 F0 DA 55 8B EC 53 56 33 C9 33 DB 8B 4D 0C 8B 55 10 8B 75 08 4E 4A 83 }

  condition:
    $a at pe.entry_point
}