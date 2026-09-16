rule TTP_XOR_WriteProcessMemory_34c5 {
  strings:
    $key_34c5 = { 63 b7 [2] 51 95 [2] 57 a0 [2] 79 a0 [2] 46 bc }

  condition:
    any of them
}