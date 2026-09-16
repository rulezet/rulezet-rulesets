rule TTP_XOR_WriteProcessMemory_e0a2 {
  strings:
    $key_e0a2 = { b7 d0 [2] 85 f2 [2] 83 c7 [2] ad c7 [2] 92 db }

  condition:
    any of them
}