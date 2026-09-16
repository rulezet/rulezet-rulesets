rule TTP_XOR_WriteProcessMemory_bdf9 {
  strings:
    $key_bdf9 = { ea 8b [2] d8 a9 [2] de 9c [2] f0 9c [2] cf 80 }

  condition:
    any of them
}