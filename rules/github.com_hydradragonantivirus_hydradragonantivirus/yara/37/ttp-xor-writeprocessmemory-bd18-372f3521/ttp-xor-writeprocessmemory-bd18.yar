rule TTP_XOR_WriteProcessMemory_bd18 {
  strings:
    $key_bd18 = { ea 6a [2] d8 48 [2] de 7d [2] f0 7d [2] cf 61 }

  condition:
    any of them
}