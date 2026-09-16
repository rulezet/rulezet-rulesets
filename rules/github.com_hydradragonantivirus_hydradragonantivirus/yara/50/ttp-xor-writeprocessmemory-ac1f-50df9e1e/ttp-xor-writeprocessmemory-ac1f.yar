rule TTP_XOR_WriteProcessMemory_ac1f {
  strings:
    $key_ac1f = { fb 6d [2] c9 4f [2] cf 7a [2] e1 7a [2] de 66 }

  condition:
    any of them
}