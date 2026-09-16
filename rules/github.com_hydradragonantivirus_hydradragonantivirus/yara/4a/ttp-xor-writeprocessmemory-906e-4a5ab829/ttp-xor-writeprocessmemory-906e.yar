rule TTP_XOR_WriteProcessMemory_906e {
  strings:
    $key_906e = { c7 1c [2] f5 3e [2] f3 0b [2] dd 0b [2] e2 17 }

  condition:
    any of them
}