rule TTP_XOR_WriteProcessMemory_fbd5 {
  strings:
    $key_fbd5 = { ac a7 [2] 9e 85 [2] 98 b0 [2] b6 b0 [2] 89 ac }

  condition:
    any of them
}