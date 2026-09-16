rule TTP_XOR_WriteProcessMemory_9331 {
  strings:
    $key_9331 = { c4 43 [2] f6 61 [2] f0 54 [2] de 54 [2] e1 48 }

  condition:
    any of them
}