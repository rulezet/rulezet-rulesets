rule TTP_XOR_WriteProcessMemory_da62 {
  strings:
    $key_da62 = { 8d 10 [2] bf 32 [2] b9 07 [2] 97 07 [2] a8 1b }

  condition:
    any of them
}