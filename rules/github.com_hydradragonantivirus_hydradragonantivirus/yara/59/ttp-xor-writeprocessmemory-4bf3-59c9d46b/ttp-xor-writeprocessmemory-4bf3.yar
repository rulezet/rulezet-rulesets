rule TTP_XOR_WriteProcessMemory_4bf3 {
  strings:
    $key_4bf3 = { 1c 81 [2] 2e a3 [2] 28 96 [2] 06 96 [2] 39 8a }

  condition:
    any of them
}