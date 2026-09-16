rule TTP_XOR_WriteProcessMemory_bdb1 {
  strings:
    $key_bdb1 = { ea c3 [2] d8 e1 [2] de d4 [2] f0 d4 [2] cf c8 }

  condition:
    any of them
}