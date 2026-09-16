rule TTP_XOR_WriteProcessMemory_957f {
  strings:
    $key_957f = { c2 0d [2] f0 2f [2] f6 1a [2] d8 1a [2] e7 06 }

  condition:
    any of them
}