rule TTP_XOR_WriteProcessMemory_900d {
  strings:
    $key_900d = { c7 7f [2] f5 5d [2] f3 68 [2] dd 68 [2] e2 74 }

  condition:
    any of them
}