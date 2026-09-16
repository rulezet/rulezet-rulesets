rule TTP_XOR_WriteProcessMemory_903f {
  strings:
    $key_903f = { c7 4d [2] f5 6f [2] f3 5a [2] dd 5a [2] e2 46 }

  condition:
    any of them
}