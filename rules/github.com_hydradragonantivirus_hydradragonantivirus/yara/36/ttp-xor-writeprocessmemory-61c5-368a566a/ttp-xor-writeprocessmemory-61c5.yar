rule TTP_XOR_WriteProcessMemory_61c5 {
  strings:
    $key_61c5 = { 36 b7 [2] 04 95 [2] 02 a0 [2] 2c a0 [2] 13 bc }

  condition:
    any of them
}