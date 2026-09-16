rule TTP_XOR_WriteProcessMemory_807f {
  strings:
    $key_807f = { d7 0d [2] e5 2f [2] e3 1a [2] cd 1a [2] f2 06 }

  condition:
    any of them
}