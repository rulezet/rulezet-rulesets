rule TTP_XOR_WriteProcessMemory_f652 {
  strings:
    $key_f652 = { a1 20 [2] 93 02 [2] 95 37 [2] bb 37 [2] 84 2b }

  condition:
    any of them
}