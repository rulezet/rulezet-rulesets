rule TTP_XOR_WriteProcessMemory_d257 {
  strings:
    $key_d257 = { 85 25 [2] b7 07 [2] b1 32 [2] 9f 32 [2] a0 2e }

  condition:
    any of them
}