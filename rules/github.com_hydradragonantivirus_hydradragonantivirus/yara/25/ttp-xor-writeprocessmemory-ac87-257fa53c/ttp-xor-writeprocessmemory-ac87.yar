rule TTP_XOR_WriteProcessMemory_ac87 {
  strings:
    $key_ac87 = { fb f5 [2] c9 d7 [2] cf e2 [2] e1 e2 [2] de fe }

  condition:
    any of them
}