rule TTP_XOR_WriteProcessMemory_978d {
  strings:
    $key_978d = { c0 ff [2] f2 dd [2] f4 e8 [2] da e8 [2] e5 f4 }

  condition:
    any of them
}