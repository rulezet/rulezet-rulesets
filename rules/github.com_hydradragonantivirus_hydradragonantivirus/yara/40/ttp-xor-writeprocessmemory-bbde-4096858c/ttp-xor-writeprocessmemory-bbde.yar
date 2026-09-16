rule TTP_XOR_WriteProcessMemory_bbde {
  strings:
    $key_bbde = { ec ac [2] de 8e [2] d8 bb [2] f6 bb [2] c9 a7 }

  condition:
    any of them
}