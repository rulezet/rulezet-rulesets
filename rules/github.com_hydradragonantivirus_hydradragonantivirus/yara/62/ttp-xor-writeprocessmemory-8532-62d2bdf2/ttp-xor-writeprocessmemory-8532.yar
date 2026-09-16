rule TTP_XOR_WriteProcessMemory_8532 {
  strings:
    $key_8532 = { d2 40 [2] e0 62 [2] e6 57 [2] c8 57 [2] f7 4b }

  condition:
    any of them
}