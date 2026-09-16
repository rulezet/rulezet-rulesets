rule TTP_XOR_WriteProcessMemory_0bf3 {
  strings:
    $key_0bf3 = { 5c 81 [2] 6e a3 [2] 68 96 [2] 46 96 [2] 79 8a }

  condition:
    any of them
}