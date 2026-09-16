rule TTP_XOR_WriteProcessMemory_bd7c {
  strings:
    $key_bd7c = { ea 0e [2] d8 2c [2] de 19 [2] f0 19 [2] cf 05 }

  condition:
    any of them
}