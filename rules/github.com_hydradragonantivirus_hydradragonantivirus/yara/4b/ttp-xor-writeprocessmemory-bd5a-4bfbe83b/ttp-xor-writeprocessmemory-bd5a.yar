rule TTP_XOR_WriteProcessMemory_bd5a {
  strings:
    $key_bd5a = { ea 28 [2] d8 0a [2] de 3f [2] f0 3f [2] cf 23 }

  condition:
    any of them
}