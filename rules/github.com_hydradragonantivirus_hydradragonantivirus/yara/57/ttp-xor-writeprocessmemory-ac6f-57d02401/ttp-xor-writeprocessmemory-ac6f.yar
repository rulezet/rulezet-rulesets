rule TTP_XOR_WriteProcessMemory_ac6f {
  strings:
    $key_ac6f = { fb 1d [2] c9 3f [2] cf 0a [2] e1 0a [2] de 16 }

  condition:
    any of them
}