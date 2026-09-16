rule TTP_XOR_WriteProcessMemory_74d5 {
  strings:
    $key_74d5 = { 23 a7 [2] 11 85 [2] 17 b0 [2] 39 b0 [2] 06 ac }

  condition:
    any of them
}