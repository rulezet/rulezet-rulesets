rule TTP_XOR_WriteProcessMemory_6cd5 {
  strings:
    $key_6cd5 = { 3b a7 [2] 09 85 [2] 0f b0 [2] 21 b0 [2] 1e ac }

  condition:
    any of them
}