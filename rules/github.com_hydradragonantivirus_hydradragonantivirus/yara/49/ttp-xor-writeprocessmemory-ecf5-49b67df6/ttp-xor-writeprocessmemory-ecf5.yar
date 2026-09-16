rule TTP_XOR_WriteProcessMemory_ecf5 {
  strings:
    $key_ecf5 = { bb 87 [2] 89 a5 [2] 8f 90 [2] a1 90 [2] 9e 8c }

  condition:
    any of them
}