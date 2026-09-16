rule TTP_XOR_WriteProcessMemory_d273 {
  strings:
    $key_d273 = { 85 01 [2] b7 23 [2] b1 16 [2] 9f 16 [2] a0 0a }

  condition:
    any of them
}