rule TTP_XOR_WriteProcessMemory_953f {
  strings:
    $key_953f = { c2 4d [2] f0 6f [2] f6 5a [2] d8 5a [2] e7 46 }

  condition:
    any of them
}