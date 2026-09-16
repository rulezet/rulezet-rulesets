rule TTP_XOR_WriteProcessMemory_d222 {
  strings:
    $key_d222 = { 85 50 [2] b7 72 [2] b1 47 [2] 9f 47 [2] a0 5b }

  condition:
    any of them
}