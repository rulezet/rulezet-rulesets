rule TTP_XOR_WriteProcessMemory_d307 {
  strings:
    $key_d307 = { 84 75 [2] b6 57 [2] b0 62 [2] 9e 62 [2] a1 7e }

  condition:
    any of them
}