rule TTP_XOR_WriteProcessMemory_91b2 {
  strings:
    $key_91b2 = { c6 c0 [2] f4 e2 [2] f2 d7 [2] dc d7 [2] e3 cb }

  condition:
    any of them
}