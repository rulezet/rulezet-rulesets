rule TTP_XOR_WriteProcessMemory_d262 {
  strings:
    $key_d262 = { 85 10 [2] b7 32 [2] b1 07 [2] 9f 07 [2] a0 1b }

  condition:
    any of them
}