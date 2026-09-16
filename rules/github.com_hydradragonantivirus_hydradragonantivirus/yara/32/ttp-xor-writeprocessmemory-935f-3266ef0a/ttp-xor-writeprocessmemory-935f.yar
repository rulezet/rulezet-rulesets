rule TTP_XOR_WriteProcessMemory_935f {
  strings:
    $key_935f = { c4 2d [2] f6 0f [2] f0 3a [2] de 3a [2] e1 26 }

  condition:
    any of them
}