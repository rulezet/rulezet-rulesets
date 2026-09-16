rule TTP_XOR_WriteProcessMemory_e9c3 {
  strings:
    $key_e9c3 = { be b1 [2] 8c 93 [2] 8a a6 [2] a4 a6 [2] 9b ba }

  condition:
    any of them
}