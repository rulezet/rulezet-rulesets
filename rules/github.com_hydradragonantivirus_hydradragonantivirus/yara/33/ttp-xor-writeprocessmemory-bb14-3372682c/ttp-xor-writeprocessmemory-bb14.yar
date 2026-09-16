rule TTP_XOR_WriteProcessMemory_bb14 {
  strings:
    $key_bb14 = { ec 66 [2] de 44 [2] d8 71 [2] f6 71 [2] c9 6d }

  condition:
    any of them
}