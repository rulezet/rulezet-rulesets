rule TTP_XOR_WriteProcessMemory_edd1 {
  strings:
    $key_edd1 = { ba a3 [2] 88 81 [2] 8e b4 [2] a0 b4 [2] 9f a8 }

  condition:
    any of them
}