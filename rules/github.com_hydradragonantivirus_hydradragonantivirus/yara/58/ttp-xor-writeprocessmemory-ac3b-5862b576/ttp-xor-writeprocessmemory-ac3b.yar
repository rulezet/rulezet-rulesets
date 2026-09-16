rule TTP_XOR_WriteProcessMemory_ac3b {
  strings:
    $key_ac3b = { fb 49 [2] c9 6b [2] cf 5e [2] e1 5e [2] de 42 }

  condition:
    any of them
}