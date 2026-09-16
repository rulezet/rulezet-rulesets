rule TTP_XOR_WriteProcessMemory_92ed {
  strings:
    $key_92ed = { c5 9f [2] f7 bd [2] f1 88 [2] df 88 [2] e0 94 }

  condition:
    any of them
}