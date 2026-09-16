rule TTP_XOR_WriteProcessMemory_bdfc {
  strings:
    $key_bdfc = { ea 8e [2] d8 ac [2] de 99 [2] f0 99 [2] cf 85 }

  condition:
    any of them
}