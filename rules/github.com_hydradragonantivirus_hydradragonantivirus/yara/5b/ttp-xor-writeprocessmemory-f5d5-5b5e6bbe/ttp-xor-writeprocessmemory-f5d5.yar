rule TTP_XOR_WriteProcessMemory_f5d5 {
  strings:
    $key_f5d5 = { a2 a7 [2] 90 85 [2] 96 b0 [2] b8 b0 [2] 87 ac }

  condition:
    any of them
}