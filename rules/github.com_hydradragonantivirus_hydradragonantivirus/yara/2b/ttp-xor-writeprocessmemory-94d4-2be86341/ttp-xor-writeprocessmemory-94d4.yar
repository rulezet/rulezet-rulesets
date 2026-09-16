rule TTP_XOR_WriteProcessMemory_94d4 {
  strings:
    $key_94d4 = { c3 a6 [2] f1 84 [2] f7 b1 [2] d9 b1 [2] e6 ad }

  condition:
    any of them
}