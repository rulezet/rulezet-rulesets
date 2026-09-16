rule TTP_XOR_WriteProcessMemory_5ad6 {
  strings:
    $key_5ad6 = { 0d a4 [2] 3f 86 [2] 39 b3 [2] 17 b3 [2] 28 af }

  condition:
    any of them
}