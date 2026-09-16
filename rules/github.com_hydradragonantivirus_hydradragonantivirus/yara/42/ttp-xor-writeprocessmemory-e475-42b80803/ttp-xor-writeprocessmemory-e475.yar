rule TTP_XOR_WriteProcessMemory_e475 {
  strings:
    $key_e475 = { b3 07 [2] 81 25 [2] 87 10 [2] a9 10 [2] 96 0c }

  condition:
    any of them
}