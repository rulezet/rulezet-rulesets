rule TTP_XOR_WriteProcessMemory_ede0 {
  strings:
    $key_ede0 = { ba 92 [2] 88 b0 [2] 8e 85 [2] a0 85 [2] 9f 99 }

  condition:
    any of them
}