rule TTP_XOR_WriteProcessMemory_86a1 {
  strings:
    $key_86a1 = { d1 d3 [2] e3 f1 [2] e5 c4 [2] cb c4 [2] f4 d8 }

  condition:
    any of them
}