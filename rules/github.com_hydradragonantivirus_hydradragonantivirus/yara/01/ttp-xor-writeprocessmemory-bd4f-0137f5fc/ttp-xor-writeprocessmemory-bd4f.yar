rule TTP_XOR_WriteProcessMemory_bd4f {
  strings:
    $key_bd4f = { ea 3d [2] d8 1f [2] de 2a [2] f0 2a [2] cf 36 }

  condition:
    any of them
}