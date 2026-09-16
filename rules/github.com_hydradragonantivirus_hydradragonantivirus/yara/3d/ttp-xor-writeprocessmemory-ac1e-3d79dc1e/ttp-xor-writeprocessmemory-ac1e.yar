rule TTP_XOR_WriteProcessMemory_ac1e {
  strings:
    $key_ac1e = { fb 6c [2] c9 4e [2] cf 7b [2] e1 7b [2] de 67 }

  condition:
    any of them
}