rule TTP_XOR_WriteProcessMemory_85e3 {
  strings:
    $key_85e3 = { d2 91 [2] e0 b3 [2] e6 86 [2] c8 86 [2] f7 9a }

  condition:
    any of them
}