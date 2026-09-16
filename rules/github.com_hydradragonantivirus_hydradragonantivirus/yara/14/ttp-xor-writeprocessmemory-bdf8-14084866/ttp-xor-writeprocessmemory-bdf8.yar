rule TTP_XOR_WriteProcessMemory_bdf8 {
  strings:
    $key_bdf8 = { ea 8a [2] d8 a8 [2] de 9d [2] f0 9d [2] cf 81 }

  condition:
    any of them
}