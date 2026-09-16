rule TTP_XOR_WriteProcessMemory_bd59 {
  strings:
    $key_bd59 = { ea 2b [2] d8 09 [2] de 3c [2] f0 3c [2] cf 20 }

  condition:
    any of them
}