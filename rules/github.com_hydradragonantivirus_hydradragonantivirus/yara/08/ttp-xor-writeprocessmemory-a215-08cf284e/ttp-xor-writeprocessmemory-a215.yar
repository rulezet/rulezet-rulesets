rule TTP_XOR_WriteProcessMemory_a215 {
  strings:
    $key_a215 = { f5 67 [2] c7 45 [2] c1 70 [2] ef 70 [2] d0 6c }

  condition:
    any of them
}