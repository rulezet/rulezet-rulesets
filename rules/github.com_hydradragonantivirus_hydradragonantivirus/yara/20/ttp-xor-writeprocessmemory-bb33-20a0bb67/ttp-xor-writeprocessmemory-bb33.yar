rule TTP_XOR_WriteProcessMemory_bb33 {
  strings:
    $key_bb33 = { ec 41 [2] de 63 [2] d8 56 [2] f6 56 [2] c9 4a }

  condition:
    any of them
}