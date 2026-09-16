rule TTP_XOR_WriteProcessMemory_86e7 {
  strings:
    $key_86e7 = { d1 95 [2] e3 b7 [2] e5 82 [2] cb 82 [2] f4 9e }

  condition:
    any of them
}