rule TTP_XOR_WriteProcessMemory_86d6 {
  strings:
    $key_86d6 = { d1 a4 [2] e3 86 [2] e5 b3 [2] cb b3 [2] f4 af }

  condition:
    any of them
}