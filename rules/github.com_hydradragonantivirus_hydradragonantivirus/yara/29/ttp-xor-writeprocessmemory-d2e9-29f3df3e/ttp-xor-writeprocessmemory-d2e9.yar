rule TTP_XOR_WriteProcessMemory_d2e9 {
  strings:
    $key_d2e9 = { 85 9b [2] b7 b9 [2] b1 8c [2] 9f 8c [2] a0 90 }

  condition:
    any of them
}