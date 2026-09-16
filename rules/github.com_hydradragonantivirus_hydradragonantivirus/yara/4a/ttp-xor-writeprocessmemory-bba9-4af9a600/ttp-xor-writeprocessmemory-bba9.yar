rule TTP_XOR_WriteProcessMemory_bba9 {
  strings:
    $key_bba9 = { ec db [2] de f9 [2] d8 cc [2] f6 cc [2] c9 d0 }

  condition:
    any of them
}