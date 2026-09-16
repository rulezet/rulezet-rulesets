rule TTP_XOR_WriteProcessMemory_91d6 {
  strings:
    $key_91d6 = { c6 a4 [2] f4 86 [2] f2 b3 [2] dc b3 [2] e3 af }

  condition:
    any of them
}