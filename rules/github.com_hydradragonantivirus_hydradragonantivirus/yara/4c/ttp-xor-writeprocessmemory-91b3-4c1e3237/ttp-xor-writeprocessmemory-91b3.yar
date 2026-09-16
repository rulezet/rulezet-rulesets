rule TTP_XOR_WriteProcessMemory_91b3 {
  strings:
    $key_91b3 = { c6 c1 [2] f4 e3 [2] f2 d6 [2] dc d6 [2] e3 ca }

  condition:
    any of them
}