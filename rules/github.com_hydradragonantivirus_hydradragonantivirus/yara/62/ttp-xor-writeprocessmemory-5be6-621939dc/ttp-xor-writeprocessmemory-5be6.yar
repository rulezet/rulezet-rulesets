rule TTP_XOR_WriteProcessMemory_5be6 {
  strings:
    $key_5be6 = { 0c 94 [2] 3e b6 [2] 38 83 [2] 16 83 [2] 29 9f }

  condition:
    any of them
}