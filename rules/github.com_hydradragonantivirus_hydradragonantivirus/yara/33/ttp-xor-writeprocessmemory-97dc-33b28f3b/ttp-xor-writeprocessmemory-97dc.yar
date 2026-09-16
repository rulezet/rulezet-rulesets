rule TTP_XOR_WriteProcessMemory_97dc {
  strings:
    $key_97dc = { c0 ae [2] f2 8c [2] f4 b9 [2] da b9 [2] e5 a5 }

  condition:
    any of them
}