rule TTP_XOR_WriteProcessMemory_855d {
  strings:
    $key_855d = { d2 2f [2] e0 0d [2] e6 38 [2] c8 38 [2] f7 24 }

  condition:
    any of them
}