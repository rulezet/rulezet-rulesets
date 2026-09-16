rule TTP_XOR_WriteProcessMemory_bb96 {
  strings:
    $key_bb96 = { ec e4 [2] de c6 [2] d8 f3 [2] f6 f3 [2] c9 ef }

  condition:
    any of them
}