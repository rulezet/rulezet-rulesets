rule TTP_XOR_WriteProcessMemory_ac2a {
  strings:
    $key_ac2a = { fb 58 [2] c9 7a [2] cf 4f [2] e1 4f [2] de 53 }

  condition:
    any of them
}