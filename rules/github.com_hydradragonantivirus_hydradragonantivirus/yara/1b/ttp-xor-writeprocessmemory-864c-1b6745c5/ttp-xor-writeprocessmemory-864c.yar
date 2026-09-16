rule TTP_XOR_WriteProcessMemory_864c {
  strings:
    $key_864c = { d1 3e [2] e3 1c [2] e5 29 [2] cb 29 [2] f4 35 }

  condition:
    any of them
}