rule TTP_XOR_WriteProcessMemory_86f0 {
  strings:
    $key_86f0 = { d1 82 [2] e3 a0 [2] e5 95 [2] cb 95 [2] f4 89 }

  condition:
    any of them
}