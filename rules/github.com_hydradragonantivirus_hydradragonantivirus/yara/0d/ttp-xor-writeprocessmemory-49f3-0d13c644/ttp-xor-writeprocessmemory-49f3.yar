rule TTP_XOR_WriteProcessMemory_49f3 {
  strings:
    $key_49f3 = { 1e 81 [2] 2c a3 [2] 2a 96 [2] 04 96 [2] 3b 8a }

  condition:
    any of them
}