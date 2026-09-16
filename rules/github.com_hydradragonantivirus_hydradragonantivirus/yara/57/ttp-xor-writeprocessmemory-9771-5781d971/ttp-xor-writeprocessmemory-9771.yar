rule TTP_XOR_WriteProcessMemory_9771 {
  strings:
    $key_9771 = { c0 03 [2] f2 21 [2] f4 14 [2] da 14 [2] e5 08 }

  condition:
    any of them
}