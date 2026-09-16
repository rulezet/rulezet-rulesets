rule TTP_XOR_WriteProcessMemory_86e4 {
  strings:
    $key_86e4 = { d1 96 [2] e3 b4 [2] e5 81 [2] cb 81 [2] f4 9d }

  condition:
    any of them
}