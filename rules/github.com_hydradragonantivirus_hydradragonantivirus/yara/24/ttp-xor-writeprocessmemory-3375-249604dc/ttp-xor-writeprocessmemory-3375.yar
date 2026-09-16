rule TTP_XOR_WriteProcessMemory_3375 {
  strings:
    $key_3375 = { 64 07 [2] 56 25 [2] 50 10 [2] 7e 10 [2] 41 0c }

  condition:
    any of them
}