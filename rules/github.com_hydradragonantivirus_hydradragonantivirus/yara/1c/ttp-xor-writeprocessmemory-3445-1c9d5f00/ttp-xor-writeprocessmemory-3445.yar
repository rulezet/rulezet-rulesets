rule TTP_XOR_WriteProcessMemory_3445 {
  strings:
    $key_3445 = { 63 37 [2] 51 15 [2] 57 20 [2] 79 20 [2] 46 3c }

  condition:
    any of them
}