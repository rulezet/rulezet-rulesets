rule TTP_XOR_WriteProcessMemory_5de6 {
  strings:
    $key_5de6 = { 0a 94 [2] 38 b6 [2] 3e 83 [2] 10 83 [2] 2f 9f }

  condition:
    any of them
}