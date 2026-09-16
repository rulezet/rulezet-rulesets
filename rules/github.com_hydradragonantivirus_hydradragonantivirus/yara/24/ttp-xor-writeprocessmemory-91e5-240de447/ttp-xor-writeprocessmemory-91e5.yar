rule TTP_XOR_WriteProcessMemory_91e5 {
  strings:
    $key_91e5 = { c6 97 [2] f4 b5 [2] f2 80 [2] dc 80 [2] e3 9c }

  condition:
    any of them
}