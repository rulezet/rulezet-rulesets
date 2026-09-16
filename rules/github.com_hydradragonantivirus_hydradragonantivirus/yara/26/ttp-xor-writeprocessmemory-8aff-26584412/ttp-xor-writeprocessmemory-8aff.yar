rule TTP_XOR_WriteProcessMemory_8aff {
  strings:
    $key_8aff = { dd 8d [2] ef af [2] e9 9a [2] c7 9a [2] f8 86 }

  condition:
    any of them
}