rule TTP_XOR_WriteProcessMemory_23e0 {
  strings:
    $key_23e0 = { 74 92 [2] 46 b0 [2] 40 85 [2] 6e 85 [2] 51 99 }

  condition:
    any of them
}