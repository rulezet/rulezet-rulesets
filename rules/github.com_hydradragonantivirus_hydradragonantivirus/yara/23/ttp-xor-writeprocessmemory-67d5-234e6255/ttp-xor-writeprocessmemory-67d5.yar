rule TTP_XOR_WriteProcessMemory_67d5 {
  strings:
    $key_67d5 = { 30 a7 [2] 02 85 [2] 04 b0 [2] 2a b0 [2] 15 ac }

  condition:
    any of them
}