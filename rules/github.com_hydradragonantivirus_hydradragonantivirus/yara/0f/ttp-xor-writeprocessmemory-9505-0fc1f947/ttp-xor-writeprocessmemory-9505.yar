rule TTP_XOR_WriteProcessMemory_9505 {
  strings:
    $key_9505 = { c2 77 [2] f0 55 [2] f6 60 [2] d8 60 [2] e7 7c }

  condition:
    any of them
}