rule TTP_XOR_WriteProcessMemory_bd5f {
  strings:
    $key_bd5f = { ea 2d [2] d8 0f [2] de 3a [2] f0 3a [2] cf 26 }

  condition:
    any of them
}