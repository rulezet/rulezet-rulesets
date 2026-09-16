rule TTP_XOR_WriteProcessMemory_8279 {
  strings:
    $key_8279 = { d5 0b [2] e7 29 [2] e1 1c [2] cf 1c [2] f0 00 }

  condition:
    any of them
}