rule TTP_XOR_WriteProcessMemory_937f {
  strings:
    $key_937f = { c4 0d [2] f6 2f [2] f0 1a [2] de 1a [2] e1 06 }

  condition:
    any of them
}