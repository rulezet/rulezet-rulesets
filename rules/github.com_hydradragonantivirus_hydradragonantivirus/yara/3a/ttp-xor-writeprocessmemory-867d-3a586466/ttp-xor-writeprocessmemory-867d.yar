rule TTP_XOR_WriteProcessMemory_867d {
  strings:
    $key_867d = { d1 0f [2] e3 2d [2] e5 18 [2] cb 18 [2] f4 04 }

  condition:
    any of them
}