rule TTP_XOR_WriteProcessMemory_da21 {
  strings:
    $key_da21 = { 8d 53 [2] bf 71 [2] b9 44 [2] 97 44 [2] a8 58 }

  condition:
    any of them
}