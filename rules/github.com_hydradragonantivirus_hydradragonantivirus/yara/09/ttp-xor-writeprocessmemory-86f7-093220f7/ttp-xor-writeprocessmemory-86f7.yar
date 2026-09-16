rule TTP_XOR_WriteProcessMemory_86f7 {
  strings:
    $key_86f7 = { d1 85 [2] e3 a7 [2] e5 92 [2] cb 92 [2] f4 8e }

  condition:
    any of them
}