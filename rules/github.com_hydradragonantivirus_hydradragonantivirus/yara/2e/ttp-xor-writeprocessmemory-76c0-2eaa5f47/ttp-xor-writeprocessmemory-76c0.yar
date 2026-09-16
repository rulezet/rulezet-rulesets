rule TTP_XOR_WriteProcessMemory_76c0 {
  strings:
    $key_76c0 = { 21 b2 [2] 13 90 [2] 15 a5 [2] 3b a5 [2] 04 b9 }

  condition:
    any of them
}