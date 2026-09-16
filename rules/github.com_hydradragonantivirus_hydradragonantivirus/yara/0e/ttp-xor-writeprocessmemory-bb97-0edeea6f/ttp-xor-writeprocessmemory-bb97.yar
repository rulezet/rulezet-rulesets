rule TTP_XOR_WriteProcessMemory_bb97 {
  strings:
    $key_bb97 = { ec e5 [2] de c7 [2] d8 f2 [2] f6 f2 [2] c9 ee }

  condition:
    any of them
}