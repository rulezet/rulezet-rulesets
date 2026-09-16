rule TTP_XOR_WriteProcessMemory_d311 {
  strings:
    $key_d311 = { 84 63 [2] b6 41 [2] b0 74 [2] 9e 74 [2] a1 68 }

  condition:
    any of them
}