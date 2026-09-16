rule TTP_XOR_WriteProcessMemory_6306 {
  strings:
    $key_6306 = { 34 74 [2] 06 56 [2] 00 63 [2] 2e 63 [2] 11 7f }

  condition:
    any of them
}