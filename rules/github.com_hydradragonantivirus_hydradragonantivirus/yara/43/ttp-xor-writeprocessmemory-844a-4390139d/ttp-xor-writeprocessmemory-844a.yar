rule TTP_XOR_WriteProcessMemory_844a {
  strings:
    $key_844a = { d3 38 [2] e1 1a [2] e7 2f [2] c9 2f [2] f6 33 }

  condition:
    any of them
}