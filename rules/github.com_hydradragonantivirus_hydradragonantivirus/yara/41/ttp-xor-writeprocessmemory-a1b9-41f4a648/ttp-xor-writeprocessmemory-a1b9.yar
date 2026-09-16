rule TTP_XOR_WriteProcessMemory_a1b9 {
  strings:
    $key_a1b9 = { f6 cb [2] c4 e9 [2] c2 dc [2] ec dc [2] d3 c0 }

  condition:
    any of them
}