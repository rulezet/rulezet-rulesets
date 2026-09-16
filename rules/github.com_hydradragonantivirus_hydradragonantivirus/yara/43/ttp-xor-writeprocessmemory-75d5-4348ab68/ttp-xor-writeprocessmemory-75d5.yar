rule TTP_XOR_WriteProcessMemory_75d5 {
  strings:
    $key_75d5 = { 22 a7 [2] 10 85 [2] 16 b0 [2] 38 b0 [2] 07 ac }

  condition:
    any of them
}