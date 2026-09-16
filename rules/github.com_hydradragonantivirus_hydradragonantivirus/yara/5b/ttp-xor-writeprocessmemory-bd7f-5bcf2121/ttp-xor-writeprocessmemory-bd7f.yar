rule TTP_XOR_WriteProcessMemory_bd7f {
  strings:
    $key_bd7f = { ea 0d [2] d8 2f [2] de 1a [2] f0 1a [2] cf 06 }

  condition:
    any of them
}