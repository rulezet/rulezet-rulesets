rule TTP_XOR_WriteProcessMemory_06e0 {
  strings:
    $key_06e0 = { 51 92 [2] 63 b0 [2] 65 85 [2] 4b 85 [2] 74 99 }

  condition:
    any of them
}