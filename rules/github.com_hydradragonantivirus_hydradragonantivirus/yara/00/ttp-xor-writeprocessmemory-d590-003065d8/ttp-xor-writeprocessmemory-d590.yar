rule TTP_XOR_WriteProcessMemory_d590 {
  strings:
    $key_d590 = { 82 e2 [2] b0 c0 [2] b6 f5 [2] 98 f5 [2] a7 e9 }

  condition:
    any of them
}