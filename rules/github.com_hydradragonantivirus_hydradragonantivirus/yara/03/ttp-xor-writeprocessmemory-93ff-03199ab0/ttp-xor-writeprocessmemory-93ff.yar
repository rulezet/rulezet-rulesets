rule TTP_XOR_WriteProcessMemory_93ff {
  strings:
    $key_93ff = { c4 8d [2] f6 af [2] f0 9a [2] de 9a [2] e1 86 }

  condition:
    any of them
}