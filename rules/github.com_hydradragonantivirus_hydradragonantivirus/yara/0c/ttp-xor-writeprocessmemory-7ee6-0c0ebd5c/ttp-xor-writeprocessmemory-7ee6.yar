rule TTP_XOR_WriteProcessMemory_7ee6 {
  strings:
    $key_7ee6 = { 29 94 [2] 1b b6 [2] 1d 83 [2] 33 83 [2] 0c 9f }

  condition:
    any of them
}