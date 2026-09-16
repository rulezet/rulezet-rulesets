rule TTP_XOR_WriteProcessMemory_3cd5 {
  strings:
    $key_3cd5 = { 6b a7 [2] 59 85 [2] 5f b0 [2] 71 b0 [2] 4e ac }

  condition:
    any of them
}