rule TTP_XOR_WriteProcessMemory_7bf3 {
  strings:
    $key_7bf3 = { 2c 81 [2] 1e a3 [2] 18 96 [2] 36 96 [2] 09 8a }

  condition:
    any of them
}