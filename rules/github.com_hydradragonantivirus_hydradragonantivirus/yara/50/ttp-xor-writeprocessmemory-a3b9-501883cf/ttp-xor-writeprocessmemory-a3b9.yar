rule TTP_XOR_WriteProcessMemory_a3b9 {
  strings:
    $key_a3b9 = { f4 cb [2] c6 e9 [2] c0 dc [2] ee dc [2] d1 c0 }

  condition:
    any of them
}