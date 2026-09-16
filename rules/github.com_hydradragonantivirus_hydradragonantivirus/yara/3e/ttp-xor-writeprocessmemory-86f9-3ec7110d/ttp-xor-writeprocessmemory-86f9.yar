rule TTP_XOR_WriteProcessMemory_86f9 {
  strings:
    $key_86f9 = { d1 8b [2] e3 a9 [2] e5 9c [2] cb 9c [2] f4 80 }

  condition:
    any of them
}