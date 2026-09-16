rule TTP_XOR_WriteProcessMemory_94f6 {
  strings:
    $key_94f6 = { c3 84 [2] f1 a6 [2] f7 93 [2] d9 93 [2] e6 8f }

  condition:
    any of them
}