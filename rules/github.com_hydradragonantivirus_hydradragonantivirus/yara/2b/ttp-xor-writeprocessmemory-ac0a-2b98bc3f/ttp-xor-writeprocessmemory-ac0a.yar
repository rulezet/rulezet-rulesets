rule TTP_XOR_WriteProcessMemory_ac0a {
  strings:
    $key_ac0a = { fb 78 [2] c9 5a [2] cf 6f [2] e1 6f [2] de 73 }

  condition:
    any of them
}