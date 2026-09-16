rule TTP_XOR_WriteProcessMemory_91c3 {
  strings:
    $key_91c3 = { c6 b1 [2] f4 93 [2] f2 a6 [2] dc a6 [2] e3 ba }

  condition:
    any of them
}