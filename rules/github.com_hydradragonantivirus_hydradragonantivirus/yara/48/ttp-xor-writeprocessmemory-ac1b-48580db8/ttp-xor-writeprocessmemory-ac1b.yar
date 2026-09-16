rule TTP_XOR_WriteProcessMemory_ac1b {
  strings:
    $key_ac1b = { fb 69 [2] c9 4b [2] cf 7e [2] e1 7e [2] de 62 }

  condition:
    any of them
}