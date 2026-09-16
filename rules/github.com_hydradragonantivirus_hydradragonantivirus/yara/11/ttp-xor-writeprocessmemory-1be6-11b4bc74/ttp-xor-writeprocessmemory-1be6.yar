rule TTP_XOR_WriteProcessMemory_1be6 {
  strings:
    $key_1be6 = { 4c 94 [2] 7e b6 [2] 78 83 [2] 56 83 [2] 69 9f }

  condition:
    any of them
}