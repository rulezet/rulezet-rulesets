rule TTP_XOR_WriteProcessMemory_fec5 {
  strings:
    $key_fec5 = { a9 b7 [2] 9b 95 [2] 9d a0 [2] b3 a0 [2] 8c bc }

  condition:
    any of them
}