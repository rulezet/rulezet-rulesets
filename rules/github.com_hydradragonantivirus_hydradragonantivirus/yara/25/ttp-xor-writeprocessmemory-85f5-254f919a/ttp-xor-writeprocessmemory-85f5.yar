rule TTP_XOR_WriteProcessMemory_85f5 {
  strings:
    $key_85f5 = { d2 87 [2] e0 a5 [2] e6 90 [2] c8 90 [2] f7 8c }

  condition:
    any of them
}