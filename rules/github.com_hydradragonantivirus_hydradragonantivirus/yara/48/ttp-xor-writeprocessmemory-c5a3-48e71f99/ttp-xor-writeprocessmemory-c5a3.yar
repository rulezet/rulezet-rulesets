rule TTP_XOR_WriteProcessMemory_c5a3 {
  strings:
    $key_c5a3 = { 92 d1 [2] a0 f3 [2] a6 c6 [2] 88 c6 [2] b7 da }

  condition:
    any of them
}