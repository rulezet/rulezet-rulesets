rule TTP_XOR_WriteProcessMemory_6987 {
  strings:
    $key_6987 = { 3e f5 [2] 0c d7 [2] 0a e2 [2] 24 e2 [2] 1b fe }

  condition:
    any of them
}