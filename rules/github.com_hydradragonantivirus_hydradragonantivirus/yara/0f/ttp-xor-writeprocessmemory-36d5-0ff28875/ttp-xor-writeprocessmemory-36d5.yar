rule TTP_XOR_WriteProcessMemory_36d5 {
  strings:
    $key_36d5 = { 61 a7 [2] 53 85 [2] 55 b0 [2] 7b b0 [2] 44 ac }

  condition:
    any of them
}