rule TTP_XOR_WriteProcessMemory_21c5 {
  strings:
    $key_21c5 = { 76 b7 [2] 44 95 [2] 42 a0 [2] 6c a0 [2] 53 bc }

  condition:
    any of them
}