rule TTP_XOR_WriteProcessMemory_eccd {
  strings:
    $key_eccd = { bb bf [2] 89 9d [2] 8f a8 [2] a1 a8 [2] 9e b4 }

  condition:
    any of them
}