rule TTP_XOR_WriteProcessMemory_11c5 {
  strings:
    $key_11c5 = { 46 b7 [2] 74 95 [2] 72 a0 [2] 5c a0 [2] 63 bc }

  condition:
    any of them
}