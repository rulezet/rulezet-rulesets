rule TTP_XOR_WriteProcessMemory_a4b9 {
  strings:
    $key_a4b9 = { f3 cb [2] c1 e9 [2] c7 dc [2] e9 dc [2] d6 c0 }

  condition:
    any of them
}