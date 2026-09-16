rule TTP_XOR_WriteProcessMemory_4556 {
  strings:
    $key_4556 = { 12 24 [2] 20 06 [2] 26 33 [2] 08 33 [2] 37 2f }

  condition:
    any of them
}