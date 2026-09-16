rule TTP_XOR_WriteProcessMemory_08a4 {
  strings:
    $key_08a4 = { 5f d6 [2] 6d f4 [2] 6b c1 [2] 45 c1 [2] 7a dd }

  condition:
    any of them
}