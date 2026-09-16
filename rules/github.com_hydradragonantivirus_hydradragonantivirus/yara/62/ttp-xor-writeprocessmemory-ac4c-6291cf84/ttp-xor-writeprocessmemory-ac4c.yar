rule TTP_XOR_WriteProcessMemory_ac4c {
  strings:
    $key_ac4c = { fb 3e [2] c9 1c [2] cf 29 [2] e1 29 [2] de 35 }

  condition:
    any of them
}