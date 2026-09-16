rule TTP_XOR_WriteProcessMemory_8468 {
  strings:
    $key_8468 = { d3 1a [2] e1 38 [2] e7 0d [2] c9 0d [2] f6 11 }

  condition:
    any of them
}