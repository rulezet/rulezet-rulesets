rule TTP_XOR_WriteProcessMemory_9790 {
  strings:
    $key_9790 = { c0 e2 [2] f2 c0 [2] f4 f5 [2] da f5 [2] e5 e9 }

  condition:
    any of them
}