rule TTP_XOR_WriteProcessMemory_854a {
  strings:
    $key_854a = { d2 38 [2] e0 1a [2] e6 2f [2] c8 2f [2] f7 33 }

  condition:
    any of them
}