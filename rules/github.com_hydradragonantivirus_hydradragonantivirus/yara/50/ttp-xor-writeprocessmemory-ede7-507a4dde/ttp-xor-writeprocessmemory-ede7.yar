rule TTP_XOR_WriteProcessMemory_ede7 {
  strings:
    $key_ede7 = { ba 95 [2] 88 b7 [2] 8e 82 [2] a0 82 [2] 9f 9e }

  condition:
    any of them
}