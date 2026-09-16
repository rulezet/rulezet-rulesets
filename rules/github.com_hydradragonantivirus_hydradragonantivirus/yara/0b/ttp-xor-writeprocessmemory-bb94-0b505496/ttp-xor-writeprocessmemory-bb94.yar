rule TTP_XOR_WriteProcessMemory_bb94 {
  strings:
    $key_bb94 = { ec e6 [2] de c4 [2] d8 f1 [2] f6 f1 [2] c9 ed }

  condition:
    any of them
}