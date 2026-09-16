rule TTP_XOR_WriteProcessMemory_bd4c {
  strings:
    $key_bd4c = { ea 3e [2] d8 1c [2] de 29 [2] f0 29 [2] cf 35 }

  condition:
    any of them
}