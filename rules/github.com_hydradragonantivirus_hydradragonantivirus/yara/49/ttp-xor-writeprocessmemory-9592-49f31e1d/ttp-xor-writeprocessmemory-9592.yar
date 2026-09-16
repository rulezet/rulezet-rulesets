rule TTP_XOR_WriteProcessMemory_9592 {
  strings:
    $key_9592 = { c2 e0 [2] f0 c2 [2] f6 f7 [2] d8 f7 [2] e7 eb }

  condition:
    any of them
}