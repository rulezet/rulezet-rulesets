rule TTP_XOR_WriteProcessMemory_1475 {
  strings:
    $key_1475 = { 43 07 [2] 71 25 [2] 77 10 [2] 59 10 [2] 66 0c }

  condition:
    any of them
}