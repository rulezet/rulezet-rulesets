rule TTP_XOR_WriteProcessMemory_4de1 {
  strings:
    $key_4de1 = { 1a 93 [2] 28 b1 [2] 2e 84 [2] 00 84 [2] 3f 98 }

  condition:
    any of them
}