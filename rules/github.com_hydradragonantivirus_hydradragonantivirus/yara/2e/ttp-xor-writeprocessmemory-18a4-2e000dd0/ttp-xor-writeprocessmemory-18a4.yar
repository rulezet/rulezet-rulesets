rule TTP_XOR_WriteProcessMemory_18a4 {
  strings:
    $key_18a4 = { 4f d6 [2] 7d f4 [2] 7b c1 [2] 55 c1 [2] 6a dd }

  condition:
    any of them
}