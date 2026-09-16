rule TTP_XOR_WriteProcessMemory_94b4 {
  strings:
    $key_94b4 = { c3 c6 [2] f1 e4 [2] f7 d1 [2] d9 d1 [2] e6 cd }

  condition:
    any of them
}