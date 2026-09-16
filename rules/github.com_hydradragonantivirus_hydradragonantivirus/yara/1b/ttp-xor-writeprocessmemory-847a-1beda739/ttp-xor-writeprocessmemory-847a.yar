rule TTP_XOR_WriteProcessMemory_847a {
  strings:
    $key_847a = { d3 08 [2] e1 2a [2] e7 1f [2] c9 1f [2] f6 03 }

  condition:
    any of them
}