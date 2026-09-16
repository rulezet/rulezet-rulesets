rule TTP_XOR_WriteProcessMemory_f629 {
  strings:
    $key_f629 = { a1 5b [2] 93 79 [2] 95 4c [2] bb 4c [2] 84 50 }

  condition:
    any of them
}