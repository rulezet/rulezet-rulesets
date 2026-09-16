rule TTP_XOR_WriteProcessMemory_8587 {
  strings:
    $key_8587 = { d2 f5 [2] e0 d7 [2] e6 e2 [2] c8 e2 [2] f7 fe }

  condition:
    any of them
}