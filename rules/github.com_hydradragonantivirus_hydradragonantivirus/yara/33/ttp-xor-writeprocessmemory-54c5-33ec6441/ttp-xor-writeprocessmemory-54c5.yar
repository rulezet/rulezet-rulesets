rule TTP_XOR_WriteProcessMemory_54c5 {
  strings:
    $key_54c5 = { 03 b7 [2] 31 95 [2] 37 a0 [2] 19 a0 [2] 26 bc }

  condition:
    any of them
}