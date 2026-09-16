rule TTP_XOR_WriteProcessMemory_e9c1 {
  strings:
    $key_e9c1 = { be b3 [2] 8c 91 [2] 8a a4 [2] a4 a4 [2] 9b b8 }

  condition:
    any of them
}