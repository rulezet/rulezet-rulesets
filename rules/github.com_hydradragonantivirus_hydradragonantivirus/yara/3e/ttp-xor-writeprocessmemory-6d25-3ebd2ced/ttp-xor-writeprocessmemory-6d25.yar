rule TTP_XOR_WriteProcessMemory_6d25 {
  strings:
    $key_6d25 = { 3a 57 [2] 08 75 [2] 0e 40 [2] 20 40 [2] 1f 5c }

  condition:
    any of them
}