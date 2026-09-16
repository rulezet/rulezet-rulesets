rule TTP_XOR_WriteProcessMemory_21f5 {
  strings:
    $key_21f5 = { 76 87 [2] 44 a5 [2] 42 90 [2] 6c 90 [2] 53 8c }

  condition:
    any of them
}