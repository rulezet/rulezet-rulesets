rule TTP_XOR_WriteProcessMemory_31a5 {
  strings:
    $key_31a5 = { 66 d7 [2] 54 f5 [2] 52 c0 [2] 7c c0 [2] 43 dc }

  condition:
    any of them
}