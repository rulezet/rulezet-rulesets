rule TTP_XOR_WriteProcessMemory_5a82 {
  strings:
    $key_5a82 = { 0d f0 [2] 3f d2 [2] 39 e7 [2] 17 e7 [2] 28 fb }

  condition:
    any of them
}