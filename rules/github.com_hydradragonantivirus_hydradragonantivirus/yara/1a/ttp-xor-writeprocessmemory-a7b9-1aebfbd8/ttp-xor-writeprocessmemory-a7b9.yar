rule TTP_XOR_WriteProcessMemory_a7b9 {
  strings:
    $key_a7b9 = { f0 cb [2] c2 e9 [2] c4 dc [2] ea dc [2] d5 c0 }

  condition:
    any of them
}