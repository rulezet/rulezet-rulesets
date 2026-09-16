rule TTP_XOR_WriteProcessMemory_5675 {
  strings:
    $key_5675 = { 01 07 [2] 33 25 [2] 35 10 [2] 1b 10 [2] 24 0c }

  condition:
    any of them
}