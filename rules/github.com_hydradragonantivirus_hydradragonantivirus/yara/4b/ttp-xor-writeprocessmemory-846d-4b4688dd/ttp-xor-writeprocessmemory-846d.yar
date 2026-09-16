rule TTP_XOR_WriteProcessMemory_846d {
  strings:
    $key_846d = { d3 1f [2] e1 3d [2] e7 08 [2] c9 08 [2] f6 14 }

  condition:
    any of them
}