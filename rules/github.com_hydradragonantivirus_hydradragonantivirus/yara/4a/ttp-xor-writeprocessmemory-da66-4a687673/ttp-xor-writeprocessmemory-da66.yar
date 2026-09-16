rule TTP_XOR_WriteProcessMemory_da66 {
  strings:
    $key_da66 = { 8d 14 [2] bf 36 [2] b9 03 [2] 97 03 [2] a8 1f }

  condition:
    any of them
}