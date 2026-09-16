rule TTP_XOR_WriteProcessMemory_72c5 {
  strings:
    $key_72c5 = { 25 b7 [2] 17 95 [2] 11 a0 [2] 3f a0 [2] 00 bc }

  condition:
    any of them
}