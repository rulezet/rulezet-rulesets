rule TTP_XOR_WriteProcessMemory_bb76 {
  strings:
    $key_bb76 = { ec 04 [2] de 26 [2] d8 13 [2] f6 13 [2] c9 0f }

  condition:
    any of them
}