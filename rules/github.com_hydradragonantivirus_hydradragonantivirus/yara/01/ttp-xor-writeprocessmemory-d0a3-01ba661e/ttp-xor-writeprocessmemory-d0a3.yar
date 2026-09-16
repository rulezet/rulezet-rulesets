rule TTP_XOR_WriteProcessMemory_d0a3 {
  strings:
    $key_d0a3 = { 87 d1 [2] b5 f3 [2] b3 c6 [2] 9d c6 [2] a2 da }

  condition:
    any of them
}