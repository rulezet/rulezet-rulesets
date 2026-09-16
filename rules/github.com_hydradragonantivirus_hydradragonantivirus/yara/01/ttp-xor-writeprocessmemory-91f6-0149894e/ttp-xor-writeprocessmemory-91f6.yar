rule TTP_XOR_WriteProcessMemory_91f6 {
  strings:
    $key_91f6 = { c6 84 [2] f4 a6 [2] f2 93 [2] dc 93 [2] e3 8f }

  condition:
    any of them
}