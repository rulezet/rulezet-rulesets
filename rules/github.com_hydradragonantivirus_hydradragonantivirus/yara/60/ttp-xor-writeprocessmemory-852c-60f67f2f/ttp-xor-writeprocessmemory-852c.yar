rule TTP_XOR_WriteProcessMemory_852c {
  strings:
    $key_852c = { d2 5e [2] e0 7c [2] e6 49 [2] c8 49 [2] f7 55 }

  condition:
    any of them
}