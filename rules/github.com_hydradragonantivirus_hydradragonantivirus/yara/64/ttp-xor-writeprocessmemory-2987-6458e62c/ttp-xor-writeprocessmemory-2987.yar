rule TTP_XOR_WriteProcessMemory_2987 {
  strings:
    $key_2987 = { 7e f5 [2] 4c d7 [2] 4a e2 [2] 64 e2 [2] 5b fe }

  condition:
    any of them
}