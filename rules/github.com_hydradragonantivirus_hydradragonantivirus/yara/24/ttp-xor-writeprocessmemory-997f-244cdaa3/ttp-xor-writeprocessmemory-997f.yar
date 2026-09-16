rule TTP_XOR_WriteProcessMemory_997f {
  strings:
    $key_997f = { ce 0d [2] fc 2f [2] fa 1a [2] d4 1a [2] eb 06 }

  condition:
    any of them
}