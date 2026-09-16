rule TTP_XOR_WriteProcessMemory_f607 {
  strings:
    $key_f607 = { a1 75 [2] 93 57 [2] 95 62 [2] bb 62 [2] 84 7e }

  condition:
    any of them
}