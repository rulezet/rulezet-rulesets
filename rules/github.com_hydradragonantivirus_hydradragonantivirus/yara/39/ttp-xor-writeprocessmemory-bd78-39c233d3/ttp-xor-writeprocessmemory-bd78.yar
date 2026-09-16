rule TTP_XOR_WriteProcessMemory_bd78 {
  strings:
    $key_bd78 = { ea 0a [2] d8 28 [2] de 1d [2] f0 1d [2] cf 01 }

  condition:
    any of them
}