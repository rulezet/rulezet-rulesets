rule TTP_XOR_WriteProcessMemory_09f3 {
  strings:
    $key_09f3 = { 5e 81 [2] 6c a3 [2] 6a 96 [2] 44 96 [2] 7b 8a }

  condition:
    any of them
}