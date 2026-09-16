rule TTP_XOR_WriteProcessMemory_e097 {
  strings:
    $key_e097 = { b7 e5 [2] 85 c7 [2] 83 f2 [2] ad f2 [2] 92 ee }

  condition:
    any of them
}