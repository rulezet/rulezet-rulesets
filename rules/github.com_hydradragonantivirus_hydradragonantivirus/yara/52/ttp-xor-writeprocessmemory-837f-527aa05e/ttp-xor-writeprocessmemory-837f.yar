rule TTP_XOR_WriteProcessMemory_837f {
  strings:
    $key_837f = { d4 0d [2] e6 2f [2] e0 1a [2] ce 1a [2] f1 06 }

  condition:
    any of them
}