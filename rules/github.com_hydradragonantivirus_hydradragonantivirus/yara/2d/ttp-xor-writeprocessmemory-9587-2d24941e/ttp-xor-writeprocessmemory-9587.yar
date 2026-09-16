rule TTP_XOR_WriteProcessMemory_9587 {
  strings:
    $key_9587 = { c2 f5 [2] f0 d7 [2] f6 e2 [2] d8 e2 [2] e7 fe }

  condition:
    any of them
}