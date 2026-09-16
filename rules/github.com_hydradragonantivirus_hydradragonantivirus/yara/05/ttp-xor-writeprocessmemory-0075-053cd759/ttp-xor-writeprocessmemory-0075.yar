rule TTP_XOR_WriteProcessMemory_0075 {
  strings:
    $key_0075 = { 57 07 [2] 65 25 [2] 63 10 [2] 4d 10 [2] 72 0c }

  condition:
    any of them
}