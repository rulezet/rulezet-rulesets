rule TTP_XOR_WriteProcessMemory_bd2b {
  strings:
    $key_bd2b = { ea 59 [2] d8 7b [2] de 4e [2] f0 4e [2] cf 52 }

  condition:
    any of them
}