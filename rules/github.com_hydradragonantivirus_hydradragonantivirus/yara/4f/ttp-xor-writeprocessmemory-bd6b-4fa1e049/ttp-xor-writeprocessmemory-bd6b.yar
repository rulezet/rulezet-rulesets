rule TTP_XOR_WriteProcessMemory_bd6b {
  strings:
    $key_bd6b = { ea 19 [2] d8 3b [2] de 0e [2] f0 0e [2] cf 12 }

  condition:
    any of them
}