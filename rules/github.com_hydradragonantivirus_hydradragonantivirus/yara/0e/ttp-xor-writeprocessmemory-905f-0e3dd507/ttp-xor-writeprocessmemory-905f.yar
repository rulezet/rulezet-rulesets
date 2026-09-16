rule TTP_XOR_WriteProcessMemory_905f {
  strings:
    $key_905f = { c7 2d [2] f5 0f [2] f3 3a [2] dd 3a [2] e2 26 }

  condition:
    any of them
}