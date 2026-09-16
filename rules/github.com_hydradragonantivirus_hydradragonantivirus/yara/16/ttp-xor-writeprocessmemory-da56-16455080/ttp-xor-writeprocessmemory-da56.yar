rule TTP_XOR_WriteProcessMemory_da56 {
  strings:
    $key_da56 = { 8d 24 [2] bf 06 [2] b9 33 [2] 97 33 [2] a8 2f }

  condition:
    any of them
}