rule TTP_XOR_WriteProcessMemory_926f {
  strings:
    $key_926f = { c5 1d [2] f7 3f [2] f1 0a [2] df 0a [2] e0 16 }

  condition:
    any of them
}