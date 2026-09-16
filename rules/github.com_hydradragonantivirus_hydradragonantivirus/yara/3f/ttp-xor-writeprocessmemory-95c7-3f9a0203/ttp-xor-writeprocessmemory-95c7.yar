rule TTP_XOR_WriteProcessMemory_95c7 {
  strings:
    $key_95c7 = { c2 b5 [2] f0 97 [2] f6 a2 [2] d8 a2 [2] e7 be }

  condition:
    any of them
}