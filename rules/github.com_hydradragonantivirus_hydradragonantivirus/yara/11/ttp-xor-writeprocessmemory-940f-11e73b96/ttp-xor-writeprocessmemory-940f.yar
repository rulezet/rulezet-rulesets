rule TTP_XOR_WriteProcessMemory_940f {
  strings:
    $key_940f = { c3 7d [2] f1 5f [2] f7 6a [2] d9 6a [2] e6 76 }

  condition:
    any of them
}