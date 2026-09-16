rule TTP_XOR_WriteProcessMemory_9787 {
  strings:
    $key_9787 = { c0 f5 [2] f2 d7 [2] f4 e2 [2] da e2 [2] e5 fe }

  condition:
    any of them
}