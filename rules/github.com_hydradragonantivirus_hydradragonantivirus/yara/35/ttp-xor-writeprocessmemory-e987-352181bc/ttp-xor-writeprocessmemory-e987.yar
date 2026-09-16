rule TTP_XOR_WriteProcessMemory_e987 {
  strings:
    $key_e987 = { be f5 [2] 8c d7 [2] 8a e2 [2] a4 e2 [2] 9b fe }

  condition:
    any of them
}