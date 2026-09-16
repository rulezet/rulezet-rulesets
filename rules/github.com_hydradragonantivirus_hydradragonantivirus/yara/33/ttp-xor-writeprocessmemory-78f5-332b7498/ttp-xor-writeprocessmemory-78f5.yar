rule TTP_XOR_WriteProcessMemory_78f5 {
  strings:
    $key_78f5 = { 2f 87 [2] 1d a5 [2] 1b 90 [2] 35 90 [2] 0a 8c }

  condition:
    any of them
}