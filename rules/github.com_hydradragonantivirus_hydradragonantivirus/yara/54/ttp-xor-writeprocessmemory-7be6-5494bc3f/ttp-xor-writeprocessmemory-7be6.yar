rule TTP_XOR_WriteProcessMemory_7be6 {
  strings:
    $key_7be6 = { 2c 94 [2] 1e b6 [2] 18 83 [2] 36 83 [2] 09 9f }

  condition:
    any of them
}