rule TTP_XOR_WriteProcessMemory_c260 {
  strings:
    $key_c260 = { 95 12 [2] a7 30 [2] a1 05 [2] 8f 05 [2] b0 19 }

  condition:
    any of them
}