rule TTP_XOR_WriteProcessMemory_28a4 {
  strings:
    $key_28a4 = { 7f d6 [2] 4d f4 [2] 4b c1 [2] 65 c1 [2] 5a dd }

  condition:
    any of them
}