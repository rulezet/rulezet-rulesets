rule TTP_XOR_WriteProcessMemory_86a2 {
  strings:
    $key_86a2 = { d1 d0 [2] e3 f2 [2] e5 c7 [2] cb c7 [2] f4 db }

  condition:
    any of them
}