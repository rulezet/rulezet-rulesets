rule TTP_XOR_WriteProcessMemory_bdeb {
  strings:
    $key_bdeb = { ea 99 [2] d8 bb [2] de 8e [2] f0 8e [2] cf 92 }

  condition:
    any of them
}