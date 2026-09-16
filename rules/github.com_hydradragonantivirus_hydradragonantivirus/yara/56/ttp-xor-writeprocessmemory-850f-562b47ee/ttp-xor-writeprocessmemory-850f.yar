rule TTP_XOR_WriteProcessMemory_850f {
  strings:
    $key_850f = { d2 7d [2] e0 5f [2] e6 6a [2] c8 6a [2] f7 76 }

  condition:
    any of them
}