rule TTP_XOR_WriteProcessMemory_bb78 {
  strings:
    $key_bb78 = { ec 0a [2] de 28 [2] d8 1d [2] f6 1d [2] c9 01 }

  condition:
    any of them
}