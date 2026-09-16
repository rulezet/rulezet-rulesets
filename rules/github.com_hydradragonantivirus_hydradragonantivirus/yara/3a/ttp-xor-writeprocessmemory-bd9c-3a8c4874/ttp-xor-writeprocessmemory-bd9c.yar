rule TTP_XOR_WriteProcessMemory_bd9c {
  strings:
    $key_bd9c = { ea ee [2] d8 cc [2] de f9 [2] f0 f9 [2] cf e5 }

  condition:
    any of them
}