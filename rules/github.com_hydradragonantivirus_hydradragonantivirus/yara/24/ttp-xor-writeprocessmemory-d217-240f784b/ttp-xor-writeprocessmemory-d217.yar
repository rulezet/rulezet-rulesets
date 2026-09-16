rule TTP_XOR_WriteProcessMemory_d217 {
  strings:
    $key_d217 = { 85 65 [2] b7 47 [2] b1 72 [2] 9f 72 [2] a0 6e }

  condition:
    any of them
}