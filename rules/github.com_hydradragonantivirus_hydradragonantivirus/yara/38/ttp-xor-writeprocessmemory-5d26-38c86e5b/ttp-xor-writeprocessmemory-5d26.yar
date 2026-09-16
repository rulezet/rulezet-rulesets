rule TTP_XOR_WriteProcessMemory_5d26 {
  strings:
    $key_5d26 = { 0a 54 [2] 38 76 [2] 3e 43 [2] 10 43 [2] 2f 5f }

  condition:
    any of them
}