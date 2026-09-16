rule TTP_XOR_WriteProcessMemory_8a4f {
  strings:
    $key_8a4f = { dd 3d [2] ef 1f [2] e9 2a [2] c7 2a [2] f8 36 }

  condition:
    any of them
}