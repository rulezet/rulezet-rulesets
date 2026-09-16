rule TTP_XOR_WriteProcessMemory_6705 {
  strings:
    $key_6705 = { 30 77 [2] 02 55 [2] 04 60 [2] 2a 60 [2] 15 7c }

  condition:
    any of them
}