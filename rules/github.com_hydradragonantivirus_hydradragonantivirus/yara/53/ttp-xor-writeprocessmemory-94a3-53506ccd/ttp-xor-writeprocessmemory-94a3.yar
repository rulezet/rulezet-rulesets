rule TTP_XOR_WriteProcessMemory_94a3 {
  strings:
    $key_94a3 = { c3 d1 [2] f1 f3 [2] f7 c6 [2] d9 c6 [2] e6 da }

  condition:
    any of them
}