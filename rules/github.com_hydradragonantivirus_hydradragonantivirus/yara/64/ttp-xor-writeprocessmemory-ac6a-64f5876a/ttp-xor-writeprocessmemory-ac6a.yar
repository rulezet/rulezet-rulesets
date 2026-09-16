rule TTP_XOR_WriteProcessMemory_ac6a {
  strings:
    $key_ac6a = { fb 18 [2] c9 3a [2] cf 0f [2] e1 0f [2] de 13 }

  condition:
    any of them
}