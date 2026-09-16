rule TTP_XOR_WriteProcessMemory_0284 {
  strings:
    $key_0284 = { 55 f6 [2] 67 d4 [2] 61 e1 [2] 4f e1 [2] 70 fd }

  condition:
    any of them
}