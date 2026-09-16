rule TTP_XOR_WriteProcessMemory_da76 {
  strings:
    $key_da76 = { 8d 04 [2] bf 26 [2] b9 13 [2] 97 13 [2] a8 0f }

  condition:
    any of them
}