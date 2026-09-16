rule TTP_XOR_WriteProcessMemory_c261 {
  strings:
    $key_c261 = { 95 13 [2] a7 31 [2] a1 04 [2] 8f 04 [2] b0 18 }

  condition:
    any of them
}