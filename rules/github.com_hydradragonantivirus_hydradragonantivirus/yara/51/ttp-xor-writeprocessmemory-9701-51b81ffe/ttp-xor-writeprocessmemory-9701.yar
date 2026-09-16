rule TTP_XOR_WriteProcessMemory_9701 {
  strings:
    $key_9701 = { c0 73 [2] f2 51 [2] f4 64 [2] da 64 [2] e5 78 }

  condition:
    any of them
}