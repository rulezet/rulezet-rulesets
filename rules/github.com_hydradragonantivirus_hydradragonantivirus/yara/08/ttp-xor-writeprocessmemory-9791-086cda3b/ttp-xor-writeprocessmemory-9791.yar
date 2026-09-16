rule TTP_XOR_WriteProcessMemory_9791 {
  strings:
    $key_9791 = { c0 e3 [2] f2 c1 [2] f4 f4 [2] da f4 [2] e5 e8 }

  condition:
    any of them
}