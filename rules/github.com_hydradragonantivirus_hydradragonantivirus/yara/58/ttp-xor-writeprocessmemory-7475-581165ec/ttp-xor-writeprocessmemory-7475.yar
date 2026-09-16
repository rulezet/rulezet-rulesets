rule TTP_XOR_WriteProcessMemory_7475 {
  strings:
    $key_7475 = { 23 07 [2] 11 25 [2] 17 10 [2] 39 10 [2] 06 0c }

  condition:
    any of them
}