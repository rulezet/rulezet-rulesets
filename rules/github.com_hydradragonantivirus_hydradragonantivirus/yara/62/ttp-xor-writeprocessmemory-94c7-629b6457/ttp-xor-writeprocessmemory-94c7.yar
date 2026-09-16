rule TTP_XOR_WriteProcessMemory_94c7 {
  strings:
    $key_94c7 = { c3 b5 [2] f1 97 [2] f7 a2 [2] d9 a2 [2] e6 be }

  condition:
    any of them
}