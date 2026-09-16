rule TTP_XOR_WriteProcessMemory_97ed {
  strings:
    $key_97ed = { c0 9f [2] f2 bd [2] f4 88 [2] da 88 [2] e5 94 }

  condition:
    any of them
}