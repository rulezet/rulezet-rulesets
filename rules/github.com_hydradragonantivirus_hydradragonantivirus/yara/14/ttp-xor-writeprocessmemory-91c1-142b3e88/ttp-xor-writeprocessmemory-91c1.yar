rule TTP_XOR_WriteProcessMemory_91c1 {
  strings:
    $key_91c1 = { c6 b3 [2] f4 91 [2] f2 a4 [2] dc a4 [2] e3 b8 }

  condition:
    any of them
}