rule TTP_XOR_WriteProcessMemory_3987 {
  strings:
    $key_3987 = { 6e f5 [2] 5c d7 [2] 5a e2 [2] 74 e2 [2] 4b fe }

  condition:
    any of them
}