rule TTP_XOR_WriteProcessMemory_ca90 {
  strings:
    $key_ca90 = { 9d e2 [2] af c0 [2] a9 f5 [2] 87 f5 [2] b8 e9 }

  condition:
    any of them
}