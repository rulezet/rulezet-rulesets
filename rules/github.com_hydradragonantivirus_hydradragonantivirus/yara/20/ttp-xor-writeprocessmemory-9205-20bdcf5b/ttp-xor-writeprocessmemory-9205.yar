rule TTP_XOR_WriteProcessMemory_9205 {
  strings:
    $key_9205 = { c5 77 [2] f7 55 [2] f1 60 [2] df 60 [2] e0 7c }

  condition:
    any of them
}