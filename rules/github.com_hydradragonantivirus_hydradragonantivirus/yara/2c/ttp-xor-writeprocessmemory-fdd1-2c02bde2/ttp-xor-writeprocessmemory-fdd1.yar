rule TTP_XOR_WriteProcessMemory_fdd1 {
  strings:
    $key_fdd1 = { aa a3 [2] 98 81 [2] 9e b4 [2] b0 b4 [2] 8f a8 }

  condition:
    any of them
}