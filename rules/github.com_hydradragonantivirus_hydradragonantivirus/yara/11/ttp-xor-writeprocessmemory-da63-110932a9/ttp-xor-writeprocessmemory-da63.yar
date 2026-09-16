rule TTP_XOR_WriteProcessMemory_da63 {
  strings:
    $key_da63 = { 8d 11 [2] bf 33 [2] b9 06 [2] 97 06 [2] a8 1a }

  condition:
    any of them
}