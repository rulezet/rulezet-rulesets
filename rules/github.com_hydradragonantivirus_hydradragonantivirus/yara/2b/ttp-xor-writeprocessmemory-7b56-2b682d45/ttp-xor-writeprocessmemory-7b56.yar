rule TTP_XOR_WriteProcessMemory_7b56 {
  strings:
    $key_7b56 = { 2c 24 [2] 1e 06 [2] 18 33 [2] 36 33 [2] 09 2f }

  condition:
    any of them
}