rule TTP_XOR_WriteProcessMemory_ac2f {
  strings:
    $key_ac2f = { fb 5d [2] c9 7f [2] cf 4a [2] e1 4a [2] de 56 }

  condition:
    any of them
}