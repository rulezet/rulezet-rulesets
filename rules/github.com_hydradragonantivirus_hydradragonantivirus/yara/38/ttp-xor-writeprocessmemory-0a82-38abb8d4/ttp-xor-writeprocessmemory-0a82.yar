rule TTP_XOR_WriteProcessMemory_0a82 {
  strings:
    $key_0a82 = { 5d f0 [2] 6f d2 [2] 69 e7 [2] 47 e7 [2] 78 fb }

  condition:
    any of them
}