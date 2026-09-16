rule TTP_XOR_WriteProcessMemory_26d5 {
  strings:
    $key_26d5 = { 71 a7 [2] 43 85 [2] 45 b0 [2] 6b b0 [2] 54 ac }

  condition:
    any of them
}