rule TTP_XOR_WriteProcessMemory_ac1a {
  strings:
    $key_ac1a = { fb 68 [2] c9 4a [2] cf 7f [2] e1 7f [2] de 63 }

  condition:
    any of them
}