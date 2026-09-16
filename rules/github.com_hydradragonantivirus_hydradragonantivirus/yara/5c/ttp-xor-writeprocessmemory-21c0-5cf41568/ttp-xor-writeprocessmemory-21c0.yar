rule TTP_XOR_WriteProcessMemory_21c0 {
  strings:
    $key_21c0 = { 76 b2 [2] 44 90 [2] 42 a5 [2] 6c a5 [2] 53 b9 }

  condition:
    any of them
}