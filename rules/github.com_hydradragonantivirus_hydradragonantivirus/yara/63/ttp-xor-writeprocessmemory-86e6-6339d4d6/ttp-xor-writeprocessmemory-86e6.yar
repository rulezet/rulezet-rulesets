rule TTP_XOR_WriteProcessMemory_86e6 {
  strings:
    $key_86e6 = { d1 94 [2] e3 b6 [2] e5 83 [2] cb 83 [2] f4 9f }

  condition:
    any of them
}