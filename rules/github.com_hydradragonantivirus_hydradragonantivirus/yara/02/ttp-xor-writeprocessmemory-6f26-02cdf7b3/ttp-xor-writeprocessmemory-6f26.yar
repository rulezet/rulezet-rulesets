rule TTP_XOR_WriteProcessMemory_6f26 {
  strings:
    $key_6f26 = { 38 54 [2] 0a 76 [2] 0c 43 [2] 22 43 [2] 1d 5f }

  condition:
    any of them
}