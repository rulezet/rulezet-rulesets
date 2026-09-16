rule TTP_XOR_WriteProcessMemory_91d4 {
  strings:
    $key_91d4 = { c6 a6 [2] f4 84 [2] f2 b1 [2] dc b1 [2] e3 ad }

  condition:
    any of them
}