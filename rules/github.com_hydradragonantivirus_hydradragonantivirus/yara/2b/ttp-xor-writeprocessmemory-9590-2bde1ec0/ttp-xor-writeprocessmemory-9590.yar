rule TTP_XOR_WriteProcessMemory_9590 {
  strings:
    $key_9590 = { c2 e2 [2] f0 c0 [2] f6 f5 [2] d8 f5 [2] e7 e9 }

  condition:
    any of them
}