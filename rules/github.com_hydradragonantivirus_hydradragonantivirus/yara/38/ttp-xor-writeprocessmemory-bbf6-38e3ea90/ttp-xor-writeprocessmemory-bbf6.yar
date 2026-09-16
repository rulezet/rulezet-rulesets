rule TTP_XOR_WriteProcessMemory_bbf6 {
  strings:
    $key_bbf6 = { ec 84 [2] de a6 [2] d8 93 [2] f6 93 [2] c9 8f }

  condition:
    any of them
}