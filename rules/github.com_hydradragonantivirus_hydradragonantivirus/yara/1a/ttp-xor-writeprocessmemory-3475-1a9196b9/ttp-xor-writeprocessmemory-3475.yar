rule TTP_XOR_WriteProcessMemory_3475 {
  strings:
    $key_3475 = { 63 07 [2] 51 25 [2] 57 10 [2] 79 10 [2] 46 0c }

  condition:
    any of them
}