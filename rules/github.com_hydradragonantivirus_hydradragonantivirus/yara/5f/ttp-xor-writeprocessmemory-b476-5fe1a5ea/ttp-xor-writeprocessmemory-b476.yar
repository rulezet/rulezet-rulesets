rule TTP_XOR_WriteProcessMemory_b476 {
  strings:
    $key_b476 = { e3 04 [2] d1 26 [2] d7 13 [2] f9 13 [2] c6 0f }

  condition:
    any of them
}