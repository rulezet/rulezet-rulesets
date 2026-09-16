rule TTP_XOR_WriteProcessMemory_86d1 {
  strings:
    $key_86d1 = { d1 a3 [2] e3 81 [2] e5 b4 [2] cb b4 [2] f4 a8 }

  condition:
    any of them
}