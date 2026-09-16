rule TTP_XOR_WriteProcessMemory_33c5 {
  strings:
    $key_33c5 = { 64 b7 [2] 56 95 [2] 50 a0 [2] 7e a0 [2] 41 bc }

  condition:
    any of them
}