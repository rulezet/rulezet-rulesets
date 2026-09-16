rule TTP_XOR_WriteProcessMemory_ac1d {
  strings:
    $key_ac1d = { fb 6f [2] c9 4d [2] cf 78 [2] e1 78 [2] de 64 }

  condition:
    any of them
}