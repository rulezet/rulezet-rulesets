rule TTP_XOR_WriteProcessMemory_aa2c {
  strings:
    $key_aa2c = { fd 5e [2] cf 7c [2] c9 49 [2] e7 49 [2] d8 55 }

  condition:
    any of them
}