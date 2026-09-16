rule TTP_XOR_WriteProcessMemory_3b56 {
  strings:
    $key_3b56 = { 6c 24 [2] 5e 06 [2] 58 33 [2] 76 33 [2] 49 2f }

  condition:
    any of them
}