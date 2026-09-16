rule TTP_XOR_WriteProcessMemory_bd1e {
  strings:
    $key_bd1e = { ea 6c [2] d8 4e [2] de 7b [2] f0 7b [2] cf 67 }

  condition:
    any of them
}