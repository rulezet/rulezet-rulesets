rule TTP_XOR_WriteProcessMemory_da8b {
  strings:
    $key_da8b = { 8d f9 [2] bf db [2] b9 ee [2] 97 ee [2] a8 f2 }

  condition:
    any of them
}