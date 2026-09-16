rule TTP_XOR_WriteProcessMemory_a5b9 {
  strings:
    $key_a5b9 = { f2 cb [2] c0 e9 [2] c6 dc [2] e8 dc [2] d7 c0 }

  condition:
    any of them
}