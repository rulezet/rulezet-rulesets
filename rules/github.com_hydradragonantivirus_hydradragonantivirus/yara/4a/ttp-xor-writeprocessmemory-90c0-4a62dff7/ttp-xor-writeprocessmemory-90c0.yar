rule TTP_XOR_WriteProcessMemory_90c0 {
  strings:
    $key_90c0 = { c7 b2 [2] f5 90 [2] f3 a5 [2] dd a5 [2] e2 b9 }

  condition:
    any of them
}