rule TTP_XOR_WriteProcessMemory_91d0 {
  strings:
    $key_91d0 = { c6 a2 [2] f4 80 [2] f2 b5 [2] dc b5 [2] e3 a9 }

  condition:
    any of them
}