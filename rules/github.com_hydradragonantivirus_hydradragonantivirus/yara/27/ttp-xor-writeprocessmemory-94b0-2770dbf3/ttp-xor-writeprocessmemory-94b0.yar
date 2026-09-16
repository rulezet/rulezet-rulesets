rule TTP_XOR_WriteProcessMemory_94b0 {
  strings:
    $key_94b0 = { c3 c2 [2] f1 e0 [2] f7 d5 [2] d9 d5 [2] e6 c9 }

  condition:
    any of them
}