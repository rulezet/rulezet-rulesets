rule TTP_XOR_WriteProcessMemory_5ad0 {
  strings:
    $key_5ad0 = { 0d a2 [2] 3f 80 [2] 39 b5 [2] 17 b5 [2] 28 a9 }

  condition:
    any of them
}