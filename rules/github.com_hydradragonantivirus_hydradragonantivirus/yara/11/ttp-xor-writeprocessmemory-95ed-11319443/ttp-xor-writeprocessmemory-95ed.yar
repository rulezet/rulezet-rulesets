rule TTP_XOR_WriteProcessMemory_95ed {
  strings:
    $key_95ed = { c2 9f [2] f0 bd [2] f6 88 [2] d8 88 [2] e7 94 }

  condition:
    any of them
}