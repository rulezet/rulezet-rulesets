rule TTP_XOR_WriteProcessMemory_bb08 {
  strings:
    $key_bb08 = { ec 7a [2] de 58 [2] d8 6d [2] f6 6d [2] c9 71 }

  condition:
    any of them
}