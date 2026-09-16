rule TTP_XOR_WriteProcessMemory_f660 {
  strings:
    $key_f660 = { a1 12 [2] 93 30 [2] 95 05 [2] bb 05 [2] 84 19 }

  condition:
    any of them
}