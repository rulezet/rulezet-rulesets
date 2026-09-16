rule TTP_XOR_WriteProcessMemory_72f5 {
  strings:
    $key_72f5 = { 25 87 [2] 17 a5 [2] 11 90 [2] 3f 90 [2] 00 8c }

  condition:
    any of them
}