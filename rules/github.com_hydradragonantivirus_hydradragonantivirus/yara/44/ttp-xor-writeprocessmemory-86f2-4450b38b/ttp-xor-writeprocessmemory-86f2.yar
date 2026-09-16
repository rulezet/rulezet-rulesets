rule TTP_XOR_WriteProcessMemory_86f2 {
  strings:
    $key_86f2 = { d1 80 [2] e3 a2 [2] e5 97 [2] cb 97 [2] f4 8b }

  condition:
    any of them
}