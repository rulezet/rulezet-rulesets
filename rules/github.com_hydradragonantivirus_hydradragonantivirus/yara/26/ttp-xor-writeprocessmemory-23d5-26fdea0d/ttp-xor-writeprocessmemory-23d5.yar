rule TTP_XOR_WriteProcessMemory_23d5 {
  strings:
    $key_23d5 = { 74 a7 [2] 46 85 [2] 40 b0 [2] 6e b0 [2] 51 ac }

  condition:
    any of them
}