rule TTP_XOR_WriteProcessMemory_ecbb {
  strings:
    $key_ecbb = { bb c9 [2] 89 eb [2] 8f de [2] a1 de [2] 9e c2 }

  condition:
    any of them
}