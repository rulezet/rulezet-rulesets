rule TTP_XOR_WriteProcessMemory_49f2 {
  strings:
    $key_49f2 = { 1e 80 [2] 2c a2 [2] 2a 97 [2] 04 97 [2] 3b 8b }

  condition:
    any of them
}