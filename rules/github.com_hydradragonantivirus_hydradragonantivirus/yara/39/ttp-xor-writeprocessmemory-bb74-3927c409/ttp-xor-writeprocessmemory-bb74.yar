rule TTP_XOR_WriteProcessMemory_bb74 {
  strings:
    $key_bb74 = { ec 06 [2] de 24 [2] d8 11 [2] f6 11 [2] c9 0d }

  condition:
    any of them
}