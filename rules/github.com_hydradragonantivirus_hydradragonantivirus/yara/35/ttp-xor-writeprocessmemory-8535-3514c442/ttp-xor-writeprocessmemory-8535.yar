rule TTP_XOR_WriteProcessMemory_8535 {
  strings:
    $key_8535 = { d2 47 [2] e0 65 [2] e6 50 [2] c8 50 [2] f7 4c }

  condition:
    any of them
}