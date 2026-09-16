rule TTP_XOR_WriteProcessMemory_38a4 {
  strings:
    $key_38a4 = { 6f d6 [2] 5d f4 [2] 5b c1 [2] 75 c1 [2] 4a dd }

  condition:
    any of them
}