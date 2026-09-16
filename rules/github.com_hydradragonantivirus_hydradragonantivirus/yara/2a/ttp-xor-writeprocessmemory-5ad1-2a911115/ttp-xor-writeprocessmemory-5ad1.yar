rule TTP_XOR_WriteProcessMemory_5ad1 {
  strings:
    $key_5ad1 = { 0d a3 [2] 3f 81 [2] 39 b4 [2] 17 b4 [2] 28 a8 }

  condition:
    any of them
}