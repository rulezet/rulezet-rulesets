rule TTP_XOR_WriteProcessMemory_91c7 {
  strings:
    $key_91c7 = { c6 b5 [2] f4 97 [2] f2 a2 [2] dc a2 [2] e3 be }

  condition:
    any of them
}