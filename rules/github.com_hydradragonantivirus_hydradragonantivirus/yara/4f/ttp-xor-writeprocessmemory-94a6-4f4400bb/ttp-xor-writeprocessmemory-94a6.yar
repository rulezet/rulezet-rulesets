rule TTP_XOR_WriteProcessMemory_94a6 {
  strings:
    $key_94a6 = { c3 d4 [2] f1 f6 [2] f7 c3 [2] d9 c3 [2] e6 df }

  condition:
    any of them
}