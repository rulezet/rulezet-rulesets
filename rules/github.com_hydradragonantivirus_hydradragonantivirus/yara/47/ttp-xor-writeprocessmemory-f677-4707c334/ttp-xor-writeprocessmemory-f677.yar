rule TTP_XOR_WriteProcessMemory_f677 {
  strings:
    $key_f677 = { a1 05 [2] 93 27 [2] 95 12 [2] bb 12 [2] 84 0e }

  condition:
    any of them
}