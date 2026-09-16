rule TTP_XOR_WriteProcessMemory_bb92 {
  strings:
    $key_bb92 = { ec e0 [2] de c2 [2] d8 f7 [2] f6 f7 [2] c9 eb }

  condition:
    any of them
}