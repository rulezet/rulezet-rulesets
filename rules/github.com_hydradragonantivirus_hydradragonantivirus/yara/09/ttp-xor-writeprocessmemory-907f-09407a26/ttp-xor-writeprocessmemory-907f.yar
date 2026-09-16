rule TTP_XOR_WriteProcessMemory_907f {
  strings:
    $key_907f = { c7 0d [2] f5 2f [2] f3 1a [2] dd 1a [2] e2 06 }

  condition:
    any of them
}