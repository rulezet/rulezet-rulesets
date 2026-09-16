rule TTP_XOR_WriteProcessMemory_deca {
  strings:
    $key_deca = { 89 b8 [2] bb 9a [2] bd af [2] 93 af [2] ac b3 }

  condition:
    any of them
}