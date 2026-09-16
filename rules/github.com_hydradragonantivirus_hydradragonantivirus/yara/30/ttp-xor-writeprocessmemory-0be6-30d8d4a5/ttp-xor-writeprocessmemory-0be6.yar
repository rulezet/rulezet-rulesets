rule TTP_XOR_WriteProcessMemory_0be6 {
  strings:
    $key_0be6 = { 5c 94 [2] 6e b6 [2] 68 83 [2] 46 83 [2] 79 9f }

  condition:
    any of them
}