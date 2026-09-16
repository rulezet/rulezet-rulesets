rule TTP_XOR_WriteProcessMemory_bb90 {
  strings:
    $key_bb90 = { ec e2 [2] de c0 [2] d8 f5 [2] f6 f5 [2] c9 e9 }

  condition:
    any of them
}