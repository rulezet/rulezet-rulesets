rule TTP_XOR_WriteProcessMemory_e0d5 {
  strings:
    $key_e0d5 = { b7 a7 [2] 85 85 [2] 83 b0 [2] ad b0 [2] 92 ac }

  condition:
    any of them
}