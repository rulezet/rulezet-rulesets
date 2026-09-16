rule TTP_XOR_WriteProcessMemory_9392 {
  strings:
    $key_9392 = { c4 e0 [2] f6 c2 [2] f0 f7 [2] de f7 [2] e1 eb }

  condition:
    any of them
}