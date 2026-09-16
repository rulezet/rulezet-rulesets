rule TTP_XOR_WriteProcessMemory_9775 {
  strings:
    $key_9775 = { c0 07 [2] f2 25 [2] f4 10 [2] da 10 [2] e5 0c }

  condition:
    any of them
}