rule TTP_XOR_WriteProcessMemory_f650 {
  strings:
    $key_f650 = { a1 22 [2] 93 00 [2] 95 35 [2] bb 35 [2] 84 29 }

  condition:
    any of them
}