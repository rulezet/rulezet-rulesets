rule TTP_XOR_WriteProcessMemory_827f {
  strings:
    $key_827f = { d5 0d [2] e7 2f [2] e1 1a [2] cf 1a [2] f0 06 }

  condition:
    any of them
}