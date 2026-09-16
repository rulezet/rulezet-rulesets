rule TTP_XOR_WriteProcessMemory_ac2c {
  strings:
    $key_ac2c = { fb 5e [2] c9 7c [2] cf 49 [2] e1 49 [2] de 55 }

  condition:
    any of them
}