rule TTP_XOR_WriteProcessMemory_bd2a {
  strings:
    $key_bd2a = { ea 58 [2] d8 7a [2] de 4f [2] f0 4f [2] cf 53 }

  condition:
    any of them
}