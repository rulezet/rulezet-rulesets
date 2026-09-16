rule TTP_XOR_WriteProcessMemory_936d {
  strings:
    $key_936d = { c4 1f [2] f6 3d [2] f0 08 [2] de 08 [2] e1 14 }

  condition:
    any of them
}