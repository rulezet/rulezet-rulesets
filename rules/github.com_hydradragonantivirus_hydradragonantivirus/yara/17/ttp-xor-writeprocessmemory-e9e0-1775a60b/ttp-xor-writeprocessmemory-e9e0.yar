rule TTP_XOR_WriteProcessMemory_e9e0 {
  strings:
    $key_e9e0 = { be 92 [2] 8c b0 [2] 8a 85 [2] a4 85 [2] 9b 99 }

  condition:
    any of them
}