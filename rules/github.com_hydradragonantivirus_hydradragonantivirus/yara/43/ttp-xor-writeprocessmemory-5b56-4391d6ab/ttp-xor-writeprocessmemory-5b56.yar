rule TTP_XOR_WriteProcessMemory_5b56 {
  strings:
    $key_5b56 = { 0c 24 [2] 3e 06 [2] 38 33 [2] 16 33 [2] 29 2f }

  condition:
    any of them
}