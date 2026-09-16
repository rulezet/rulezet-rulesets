rule TTP_XOR_WriteProcessMemory_94a5 {
  strings:
    $key_94a5 = { c3 d7 [2] f1 f5 [2] f7 c0 [2] d9 c0 [2] e6 dc }

  condition:
    any of them
}