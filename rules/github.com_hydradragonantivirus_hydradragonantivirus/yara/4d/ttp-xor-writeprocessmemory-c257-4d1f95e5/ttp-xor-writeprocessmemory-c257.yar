rule TTP_XOR_WriteProcessMemory_c257 {
  strings:
    $key_c257 = { 95 25 [2] a7 07 [2] a1 32 [2] 8f 32 [2] b0 2e }

  condition:
    any of them
}