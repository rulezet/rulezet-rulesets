rule TTP_XOR_WriteProcessMemory_904c {
  strings:
    $key_904c = { c7 3e [2] f5 1c [2] f3 29 [2] dd 29 [2] e2 35 }

  condition:
    any of them
}