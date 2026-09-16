rule TTP_XOR_WriteProcessMemory_815f {
  strings:
    $key_815f = { d6 2d [2] e4 0f [2] e2 3a [2] cc 3a [2] f3 26 }

  condition:
    any of them
}