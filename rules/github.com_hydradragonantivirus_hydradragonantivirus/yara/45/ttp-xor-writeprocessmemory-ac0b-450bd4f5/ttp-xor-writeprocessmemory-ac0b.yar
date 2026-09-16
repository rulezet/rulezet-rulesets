rule TTP_XOR_WriteProcessMemory_ac0b {
  strings:
    $key_ac0b = { fb 79 [2] c9 5b [2] cf 6e [2] e1 6e [2] de 72 }

  condition:
    any of them
}