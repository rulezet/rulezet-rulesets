rule TTP_XOR_WriteProcessMemory_bbf3 {
  strings:
    $key_bbf3 = { ec 81 [2] de a3 [2] d8 96 [2] f6 96 [2] c9 8a }

  condition:
    any of them
}