rule TTP_XOR_WriteProcessMemory_f075 {
  strings:
    $key_f075 = { a7 07 [2] 95 25 [2] 93 10 [2] bd 10 [2] 82 0c }

  condition:
    any of them
}