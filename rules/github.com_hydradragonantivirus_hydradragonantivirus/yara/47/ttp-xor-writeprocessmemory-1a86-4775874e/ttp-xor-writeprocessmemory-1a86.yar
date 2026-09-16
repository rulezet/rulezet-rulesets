rule TTP_XOR_WriteProcessMemory_1a86 {
  strings:
    $key_1a86 = { 4d f4 [2] 7f d6 [2] 79 e3 [2] 57 e3 [2] 68 ff }

  condition:
    any of them
}