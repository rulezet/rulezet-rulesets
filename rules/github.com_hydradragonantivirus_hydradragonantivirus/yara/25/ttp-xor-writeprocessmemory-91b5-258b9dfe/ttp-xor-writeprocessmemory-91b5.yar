rule TTP_XOR_WriteProcessMemory_91b5 {
  strings:
    $key_91b5 = { c6 c7 [2] f4 e5 [2] f2 d0 [2] dc d0 [2] e3 cc }

  condition:
    any of them
}