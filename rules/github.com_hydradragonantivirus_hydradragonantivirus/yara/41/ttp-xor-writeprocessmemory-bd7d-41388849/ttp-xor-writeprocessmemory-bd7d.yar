rule TTP_XOR_WriteProcessMemory_bd7d {
  strings:
    $key_bd7d = { ea 0f [2] d8 2d [2] de 18 [2] f0 18 [2] cf 04 }

  condition:
    any of them
}