rule TTP_XOR_WriteProcessMemory_86c2 {
  strings:
    $key_86c2 = { d1 b0 [2] e3 92 [2] e5 a7 [2] cb a7 [2] f4 bb }

  condition:
    any of them
}