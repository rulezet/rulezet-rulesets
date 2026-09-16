rule TTP_XOR_WriteProcessMemory_8697 {
  strings:
    $key_8697 = { d1 e5 [2] e3 c7 [2] e5 f2 [2] cb f2 [2] f4 ee }

  condition:
    any of them
}