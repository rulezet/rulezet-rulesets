rule TTP_XOR_WriteProcessMemory_15d5 {
  strings:
    $key_15d5 = { 42 a7 [2] 70 85 [2] 76 b0 [2] 58 b0 [2] 67 ac }

  condition:
    any of them
}