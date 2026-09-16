rule TTP_XOR_WriteProcessMemory_da85 {
  strings:
    $key_da85 = { 8d f7 [2] bf d5 [2] b9 e0 [2] 97 e0 [2] a8 fc }

  condition:
    any of them
}