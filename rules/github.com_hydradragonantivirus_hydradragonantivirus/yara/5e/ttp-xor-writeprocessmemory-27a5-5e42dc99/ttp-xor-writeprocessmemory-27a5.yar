rule TTP_XOR_WriteProcessMemory_27a5 {
  strings:
    $key_27a5 = { 70 d7 [2] 42 f5 [2] 44 c0 [2] 6a c0 [2] 55 dc }

  condition:
    any of them
}