rule TTP_XOR_WriteProcessMemory_4632 {
  strings:
    $key_4632 = { 11 40 [2] 23 62 [2] 25 57 [2] 0b 57 [2] 34 4b }

  condition:
    any of them
}