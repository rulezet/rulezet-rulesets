rule TTP_XOR_WriteProcessMemory_9084 {
  strings:
    $key_9084 = { c7 f6 [2] f5 d4 [2] f3 e1 [2] dd e1 [2] e2 fd }

  condition:
    any of them
}