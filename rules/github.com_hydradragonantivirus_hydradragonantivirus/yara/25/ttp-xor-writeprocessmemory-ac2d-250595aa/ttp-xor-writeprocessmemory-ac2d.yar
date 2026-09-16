rule TTP_XOR_WriteProcessMemory_ac2d {
  strings:
    $key_ac2d = { fb 5f [2] c9 7d [2] cf 48 [2] e1 48 [2] de 54 }

  condition:
    any of them
}