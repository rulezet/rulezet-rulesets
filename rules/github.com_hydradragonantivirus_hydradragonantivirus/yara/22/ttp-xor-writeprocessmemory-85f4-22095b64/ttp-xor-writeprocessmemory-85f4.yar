rule TTP_XOR_WriteProcessMemory_85f4 {
  strings:
    $key_85f4 = { d2 86 [2] e0 a4 [2] e6 91 [2] c8 91 [2] f7 8d }

  condition:
    any of them
}