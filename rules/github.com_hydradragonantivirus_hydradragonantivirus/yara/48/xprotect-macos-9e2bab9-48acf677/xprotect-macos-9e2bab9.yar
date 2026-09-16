rule XProtect_MACOS_9e2bab9 {
  meta:
    description = "MACOS.9e2bab9"

  strings:
    $a  = "FasdUAS"
    $b1 = { 18 2E 73 79 73 6F 65 78 65 63 54 45 58 54 FF FF 80 }
    $b2 = { 6B 6F 63 6C 0A FF ?? 00 04 0A 63 6F 62 6A 0A FF ?? 00 18 2E 63 6F 72 65 63 6E 74 65 2A 2A 2A 2A }
    $b3 = { 2A 2A 2A 2A 03 FF ?? 00 64 0A FF ?? 00 04 0A 70 63 6E 74 0A FF ?? 00 04 0A 54 45 58 54 0A FF ?? 00 08 0B 6B 66 72 6D 49 44 }
    $c1 = { 00 A7 00 D3 00 D2 00 D8 00 C5 00 CD 00 D2 00 C9 00 D6 00 D7 }
    $c2 = { 00 C6 00 D9 00 CD 00 D0 00 C8 00 C3 00 DA 00 C9 00 D2 00 C8 00 D3 00 D6 }
    $c3 = { 00 C6 00 D9 00 CD 00 D0 00 C8 00 C3 00 DA 00 C9 00 D6 00 D7 00 CD 00 D3 00 D2 }
    $c4 = { 00 D3 00 D7 00 C5 00 C7 00 D3 00 D1 00 D4 00 CD 00 D0 00 C9 }
    $c5 = { 00 D3 00 D7 00 C5 00 D7 00 C7 00 D6 00 CD 00 D4 00 D8 }

  condition:
    $a at 0 and filesize < 100KB and all of ($b*) and any of ($c*)
}