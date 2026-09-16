rule TTP_XOR_WriteProcessMemory_ac3c {
  strings:
    $key_ac3c = { fb 4e [2] c9 6c [2] cf 59 [2] e1 59 [2] de 45 }

  condition:
    any of them
}