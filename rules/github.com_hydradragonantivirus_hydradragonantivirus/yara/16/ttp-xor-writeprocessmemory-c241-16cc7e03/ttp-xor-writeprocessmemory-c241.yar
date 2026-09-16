rule TTP_XOR_WriteProcessMemory_c241 {
  strings:
    $key_c241 = { 95 33 [2] a7 11 [2] a1 24 [2] 8f 24 [2] b0 38 }

  condition:
    any of them
}