rule TTP_XOR_WriteProcessMemory_86e9 {
  strings:
    $key_86e9 = { d1 9b [2] e3 b9 [2] e5 8c [2] cb 8c [2] f4 90 }

  condition:
    any of them
}