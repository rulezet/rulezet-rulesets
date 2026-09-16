rule TTP_XOR_WriteProcessMemory_74c5 {
  strings:
    $key_74c5 = { 23 b7 [2] 11 95 [2] 17 a0 [2] 39 a0 [2] 06 bc }

  condition:
    any of them
}