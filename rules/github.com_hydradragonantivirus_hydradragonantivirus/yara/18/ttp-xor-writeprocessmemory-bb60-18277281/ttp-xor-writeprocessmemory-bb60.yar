rule TTP_XOR_WriteProcessMemory_bb60 {
  strings:
    $key_bb60 = { ec 12 [2] de 30 [2] d8 05 [2] f6 05 [2] c9 19 }

  condition:
    any of them
}