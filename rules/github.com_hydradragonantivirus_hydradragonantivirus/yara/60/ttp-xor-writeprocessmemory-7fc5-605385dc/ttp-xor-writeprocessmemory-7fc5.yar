rule TTP_XOR_WriteProcessMemory_7fc5 {
  strings:
    $key_7fc5 = { 28 b7 [2] 1a 95 [2] 1c a0 [2] 32 a0 [2] 0d bc }

  condition:
    any of them
}