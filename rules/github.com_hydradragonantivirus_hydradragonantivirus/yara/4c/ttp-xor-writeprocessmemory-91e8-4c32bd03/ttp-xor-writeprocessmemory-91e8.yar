rule TTP_XOR_WriteProcessMemory_91e8 {
  strings:
    $key_91e8 = { c6 9a [2] f4 b8 [2] f2 8d [2] dc 8d [2] e3 91 }

  condition:
    any of them
}