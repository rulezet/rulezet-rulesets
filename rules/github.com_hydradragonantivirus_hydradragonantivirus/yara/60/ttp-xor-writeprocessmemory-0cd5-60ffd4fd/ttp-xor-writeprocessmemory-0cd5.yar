rule TTP_XOR_WriteProcessMemory_0cd5 {
  strings:
    $key_0cd5 = { 5b a7 [2] 69 85 [2] 6f b0 [2] 41 b0 [2] 7e ac }

  condition:
    any of them
}