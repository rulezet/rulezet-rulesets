rule TTP_XOR_WriteProcessMemory_da51 {
  strings:
    $key_da51 = { 8d 23 [2] bf 01 [2] b9 34 [2] 97 34 [2] a8 28 }

  condition:
    any of them
}