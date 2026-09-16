rule TTP_XOR_WriteProcessMemory_9757 {
  strings:
    $key_9757 = { c0 25 [2] f2 07 [2] f4 32 [2] da 32 [2] e5 2e }

  condition:
    any of them
}