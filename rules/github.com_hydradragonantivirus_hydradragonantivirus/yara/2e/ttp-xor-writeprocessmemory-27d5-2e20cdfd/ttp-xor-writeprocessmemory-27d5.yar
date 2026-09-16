rule TTP_XOR_WriteProcessMemory_27d5 {
  strings:
    $key_27d5 = { 70 a7 [2] 42 85 [2] 44 b0 [2] 6a b0 [2] 55 ac }

  condition:
    any of them
}