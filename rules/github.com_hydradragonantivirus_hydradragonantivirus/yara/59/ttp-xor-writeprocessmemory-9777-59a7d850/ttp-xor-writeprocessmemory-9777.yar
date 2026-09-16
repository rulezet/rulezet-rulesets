rule TTP_XOR_WriteProcessMemory_9777 {
  strings:
    $key_9777 = { c0 05 [2] f2 27 [2] f4 12 [2] da 12 [2] e5 0e }

  condition:
    any of them
}