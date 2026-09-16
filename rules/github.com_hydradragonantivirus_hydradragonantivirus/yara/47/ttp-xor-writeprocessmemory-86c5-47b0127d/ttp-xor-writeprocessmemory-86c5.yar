rule TTP_XOR_WriteProcessMemory_86c5 {
  strings:
    $key_86c5 = { d1 b7 [2] e3 95 [2] e5 a0 [2] cb a0 [2] f4 bc }

  condition:
    any of them
}