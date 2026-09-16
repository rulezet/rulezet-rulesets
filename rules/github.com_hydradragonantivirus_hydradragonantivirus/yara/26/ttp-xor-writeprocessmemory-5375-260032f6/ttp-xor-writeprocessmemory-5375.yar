rule TTP_XOR_WriteProcessMemory_5375 {
  strings:
    $key_5375 = { 04 07 [2] 36 25 [2] 30 10 [2] 1e 10 [2] 21 0c }

  condition:
    any of them
}