rule TTP_XOR_WriteProcessMemory_866f {
  strings:
    $key_866f = { d1 1d [2] e3 3f [2] e5 0a [2] cb 0a [2] f4 16 }

  condition:
    any of them
}