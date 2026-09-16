rule TTP_XOR_WriteProcessMemory_0ec5 {
  strings:
    $key_0ec5 = { 59 b7 [2] 6b 95 [2] 6d a0 [2] 43 a0 [2] 7c bc }

  condition:
    any of them
}