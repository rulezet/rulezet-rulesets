rule TTP_XOR_WriteProcessMemory_bb28 {
  strings:
    $key_bb28 = { ec 5a [2] de 78 [2] d8 4d [2] f6 4d [2] c9 51 }

  condition:
    any of them
}