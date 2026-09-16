rule TTP_XOR_WriteProcessMemory_9687 {
  strings:
    $key_9687 = { c1 f5 [2] f3 d7 [2] f5 e2 [2] db e2 [2] e4 fe }

  condition:
    any of them
}