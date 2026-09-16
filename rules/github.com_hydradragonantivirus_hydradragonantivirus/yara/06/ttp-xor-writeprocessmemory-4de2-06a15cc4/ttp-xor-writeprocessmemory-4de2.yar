rule TTP_XOR_WriteProcessMemory_4de2 {
  strings:
    $key_4de2 = { 1a 90 [2] 28 b2 [2] 2e 87 [2] 00 87 [2] 3f 9b }

  condition:
    any of them
}