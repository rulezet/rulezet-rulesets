rule TTP_XOR_WriteProcessMemory_900c {
  strings:
    $key_900c = { c7 7e [2] f5 5c [2] f3 69 [2] dd 69 [2] e2 75 }

  condition:
    any of them
}