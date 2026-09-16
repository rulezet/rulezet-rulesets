rule TTP_XOR_WriteProcessMemory_bd5c {
  strings:
    $key_bd5c = { ea 2e [2] d8 0c [2] de 39 [2] f0 39 [2] cf 25 }

  condition:
    any of them
}