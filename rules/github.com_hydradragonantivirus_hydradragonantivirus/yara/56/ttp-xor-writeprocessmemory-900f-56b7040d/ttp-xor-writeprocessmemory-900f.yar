rule TTP_XOR_WriteProcessMemory_900f {
  strings:
    $key_900f = { c7 7d [2] f5 5f [2] f3 6a [2] dd 6a [2] e2 76 }

  condition:
    any of them
}