rule TTP_XOR_WriteProcessMemory_977f {
  strings:
    $key_977f = { c0 0d [2] f2 2f [2] f4 1a [2] da 1a [2] e5 06 }

  condition:
    any of them
}