rule TTP_XOR_WriteProcessMemory_20a4 {
  strings:
    $key_20a4 = { 77 d6 [2] 45 f4 [2] 43 c1 [2] 6d c1 [2] 52 dd }

  condition:
    any of them
}