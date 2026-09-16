rule TTP_XOR_WriteProcessMemory_7dc0 {
  strings:
    $key_7dc0 = { 2a b2 [2] 18 90 [2] 1e a5 [2] 30 a5 [2] 0f b9 }

  condition:
    any of them
}