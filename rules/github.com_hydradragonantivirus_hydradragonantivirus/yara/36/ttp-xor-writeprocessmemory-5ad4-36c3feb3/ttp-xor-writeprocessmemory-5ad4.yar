rule TTP_XOR_WriteProcessMemory_5ad4 {
  strings:
    $key_5ad4 = { 0d a6 [2] 3f 84 [2] 39 b1 [2] 17 b1 [2] 28 ad }

  condition:
    any of them
}