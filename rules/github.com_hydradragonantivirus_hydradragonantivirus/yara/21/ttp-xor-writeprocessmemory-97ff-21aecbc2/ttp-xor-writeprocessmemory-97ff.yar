rule TTP_XOR_WriteProcessMemory_97ff {
  strings:
    $key_97ff = { c0 8d [2] f2 af [2] f4 9a [2] da 9a [2] e5 86 }

  condition:
    any of them
}