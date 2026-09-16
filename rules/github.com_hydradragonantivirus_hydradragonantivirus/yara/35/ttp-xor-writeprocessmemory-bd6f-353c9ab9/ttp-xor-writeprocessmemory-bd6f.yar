rule TTP_XOR_WriteProcessMemory_bd6f {
  strings:
    $key_bd6f = { ea 1d [2] d8 3f [2] de 0a [2] f0 0a [2] cf 16 }

  condition:
    any of them
}