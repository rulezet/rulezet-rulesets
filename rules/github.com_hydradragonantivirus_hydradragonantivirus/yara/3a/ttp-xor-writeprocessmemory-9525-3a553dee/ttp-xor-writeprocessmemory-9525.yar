rule TTP_XOR_WriteProcessMemory_9525 {
  strings:
    $key_9525 = { c2 57 [2] f0 75 [2] f6 40 [2] d8 40 [2] e7 5c }

  condition:
    any of them
}