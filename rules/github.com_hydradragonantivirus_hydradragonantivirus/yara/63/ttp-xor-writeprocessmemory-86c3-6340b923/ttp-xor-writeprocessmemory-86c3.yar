rule TTP_XOR_WriteProcessMemory_86c3 {
  strings:
    $key_86c3 = { d1 b1 [2] e3 93 [2] e5 a6 [2] cb a6 [2] f4 ba }

  condition:
    any of them
}