rule TTP_XOR_WriteProcessMemory_3a86 {
  strings:
    $key_3a86 = { 6d f4 [2] 5f d6 [2] 59 e3 [2] 77 e3 [2] 48 ff }

  condition:
    any of them
}