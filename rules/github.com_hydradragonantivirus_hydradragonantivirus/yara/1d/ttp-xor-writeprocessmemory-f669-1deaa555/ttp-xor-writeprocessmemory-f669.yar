rule TTP_XOR_WriteProcessMemory_f669 {
  strings:
    $key_f669 = { a1 1b [2] 93 39 [2] 95 0c [2] bb 0c [2] 84 10 }

  condition:
    any of them
}