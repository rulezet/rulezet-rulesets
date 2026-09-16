rule TTP_XOR_WriteProcessMemory_952f {
  strings:
    $key_952f = { c2 5d [2] f0 7f [2] f6 4a [2] d8 4a [2] e7 56 }

  condition:
    any of them
}