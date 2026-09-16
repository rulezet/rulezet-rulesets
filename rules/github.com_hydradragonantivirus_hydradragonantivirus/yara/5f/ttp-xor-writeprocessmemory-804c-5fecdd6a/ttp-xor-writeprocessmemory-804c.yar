rule TTP_XOR_WriteProcessMemory_804c {
  strings:
    $key_804c = { d7 3e [2] e5 1c [2] e3 29 [2] cd 29 [2] f2 35 }

  condition:
    any of them
}