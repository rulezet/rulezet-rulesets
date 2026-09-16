rule TTP_XOR_WriteProcessMemory_bd5b {
  strings:
    $key_bd5b = { ea 29 [2] d8 0b [2] de 3e [2] f0 3e [2] cf 22 }

  condition:
    any of them
}