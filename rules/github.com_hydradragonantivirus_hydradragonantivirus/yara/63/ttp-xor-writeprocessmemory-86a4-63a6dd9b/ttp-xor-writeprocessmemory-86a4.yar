rule TTP_XOR_WriteProcessMemory_86a4 {
  strings:
    $key_86a4 = { d1 d6 [2] e3 f4 [2] e5 c1 [2] cb c1 [2] f4 dd }

  condition:
    any of them
}