rule TTP_XOR_WriteProcessMemory_3472 {
  strings:
    $key_3472 = { 63 00 [2] 51 22 [2] 57 17 [2] 79 17 [2] 46 0b }

  condition:
    any of them
}