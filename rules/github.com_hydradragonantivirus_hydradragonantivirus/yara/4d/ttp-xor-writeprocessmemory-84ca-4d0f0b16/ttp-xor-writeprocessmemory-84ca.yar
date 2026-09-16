rule TTP_XOR_WriteProcessMemory_84ca {
  strings:
    $key_84ca = { d3 b8 [2] e1 9a [2] e7 af [2] c9 af [2] f6 b3 }

  condition:
    any of them
}