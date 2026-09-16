rule TTP_XOR_WriteProcessMemory_bd2e {
  strings:
    $key_bd2e = { ea 5c [2] d8 7e [2] de 4b [2] f0 4b [2] cf 57 }

  condition:
    any of them
}