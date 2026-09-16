rule TTP_XOR_WriteProcessMemory_94c5 {
  strings:
    $key_94c5 = { c3 b7 [2] f1 95 [2] f7 a0 [2] d9 a0 [2] e6 bc }

  condition:
    any of them
}