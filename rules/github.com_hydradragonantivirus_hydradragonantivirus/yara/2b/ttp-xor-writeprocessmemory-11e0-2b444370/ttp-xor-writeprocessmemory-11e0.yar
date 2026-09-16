rule TTP_XOR_WriteProcessMemory_11e0 {
  strings:
    $key_11e0 = { 46 92 [2] 74 b0 [2] 72 85 [2] 5c 85 [2] 63 99 }

  condition:
    any of them
}