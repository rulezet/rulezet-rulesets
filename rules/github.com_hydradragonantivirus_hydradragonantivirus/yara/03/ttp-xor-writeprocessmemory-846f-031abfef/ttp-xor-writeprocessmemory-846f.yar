rule TTP_XOR_WriteProcessMemory_846f {
  strings:
    $key_846f = { d3 1d [2] e1 3f [2] e7 0a [2] c9 0a [2] f6 16 }

  condition:
    any of them
}