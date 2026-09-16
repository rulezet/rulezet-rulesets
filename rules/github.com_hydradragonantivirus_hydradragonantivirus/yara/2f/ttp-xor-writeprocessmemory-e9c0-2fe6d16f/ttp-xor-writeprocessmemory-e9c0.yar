rule TTP_XOR_WriteProcessMemory_e9c0 {
  strings:
    $key_e9c0 = { be b2 [2] 8c 90 [2] 8a a5 [2] a4 a5 [2] 9b b9 }

  condition:
    any of them
}