rule TTP_XOR_WriteProcessMemory_a0b9 {
  strings:
    $key_a0b9 = { f7 cb [2] c5 e9 [2] c3 dc [2] ed dc [2] d2 c0 }

  condition:
    any of them
}