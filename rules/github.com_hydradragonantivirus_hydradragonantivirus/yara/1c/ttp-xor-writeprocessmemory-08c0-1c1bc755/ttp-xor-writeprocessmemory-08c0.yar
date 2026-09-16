rule TTP_XOR_WriteProcessMemory_08c0 {
  strings:
    $key_08c0 = { 5f b2 [2] 6d 90 [2] 6b a5 [2] 45 a5 [2] 7a b9 }

  condition:
    any of them
}