rule TTP_XOR_WriteProcessMemory_8596 {
  strings:
    $key_8596 = { d2 e4 [2] e0 c6 [2] e6 f3 [2] c8 f3 [2] f7 ef }

  condition:
    any of them
}