rule TTP_XOR_WriteProcessMemory_5bf3 {
  strings:
    $key_5bf3 = { 0c 81 [2] 3e a3 [2] 38 96 [2] 16 96 [2] 29 8a }

  condition:
    any of them
}