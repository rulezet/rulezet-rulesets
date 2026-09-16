rule TTP_XOR_WriteProcessMemory_8418 {
  strings:
    $key_8418 = { d3 6a [2] e1 48 [2] e7 7d [2] c9 7d [2] f6 61 }

  condition:
    any of them
}