rule TTP_XOR_WriteProcessMemory_973f {
  strings:
    $key_973f = { c0 4d [2] f2 6f [2] f4 5a [2] da 5a [2] e5 46 }

  condition:
    any of them
}