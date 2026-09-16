rule TTP_XOR_WriteProcessMemory_ac0e {
  strings:
    $key_ac0e = { fb 7c [2] c9 5e [2] cf 6b [2] e1 6b [2] de 77 }

  condition:
    any of them
}