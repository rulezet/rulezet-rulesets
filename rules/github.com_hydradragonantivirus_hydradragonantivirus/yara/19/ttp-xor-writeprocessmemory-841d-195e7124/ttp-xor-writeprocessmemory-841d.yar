rule TTP_XOR_WriteProcessMemory_841d {
  strings:
    $key_841d = { d3 6f [2] e1 4d [2] e7 78 [2] c9 78 [2] f6 64 }

  condition:
    any of them
}