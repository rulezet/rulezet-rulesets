rule TTP_XOR_WriteProcessMemory_74f5 {
  strings:
    $key_74f5 = { 23 87 [2] 11 a5 [2] 17 90 [2] 39 90 [2] 06 8c }

  condition:
    any of them
}