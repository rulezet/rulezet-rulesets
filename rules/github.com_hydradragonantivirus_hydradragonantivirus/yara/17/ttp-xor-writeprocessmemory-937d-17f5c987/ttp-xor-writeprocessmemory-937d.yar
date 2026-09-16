rule TTP_XOR_WriteProcessMemory_937d {
  strings:
    $key_937d = { c4 0f [2] f6 2d [2] f0 18 [2] de 18 [2] e1 04 }

  condition:
    any of them
}