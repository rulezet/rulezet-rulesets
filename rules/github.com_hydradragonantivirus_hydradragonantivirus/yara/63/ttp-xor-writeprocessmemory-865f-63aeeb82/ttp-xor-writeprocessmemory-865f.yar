rule TTP_XOR_WriteProcessMemory_865f {
  strings:
    $key_865f = { d1 2d [2] e3 0f [2] e5 3a [2] cb 3a [2] f4 26 }

  condition:
    any of them
}