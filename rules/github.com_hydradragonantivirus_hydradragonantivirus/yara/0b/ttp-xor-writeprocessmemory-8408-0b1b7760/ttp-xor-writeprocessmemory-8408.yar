rule TTP_XOR_WriteProcessMemory_8408 {
  strings:
    $key_8408 = { d3 7a [2] e1 58 [2] e7 6d [2] c9 6d [2] f6 71 }

  condition:
    any of them
}