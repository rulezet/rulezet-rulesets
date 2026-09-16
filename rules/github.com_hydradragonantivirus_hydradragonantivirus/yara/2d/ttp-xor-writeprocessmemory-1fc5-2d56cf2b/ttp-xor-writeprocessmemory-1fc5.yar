rule TTP_XOR_WriteProcessMemory_1fc5 {
  strings:
    $key_1fc5 = { 48 b7 [2] 7a 95 [2] 7c a0 [2] 52 a0 [2] 6d bc }

  condition:
    any of them
}