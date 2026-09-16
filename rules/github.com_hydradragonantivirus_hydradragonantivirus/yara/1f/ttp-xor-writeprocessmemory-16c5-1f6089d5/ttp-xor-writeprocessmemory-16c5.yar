rule TTP_XOR_WriteProcessMemory_16c5 {
  strings:
    $key_16c5 = { 41 b7 [2] 73 95 [2] 75 a0 [2] 5b a0 [2] 64 bc }

  condition:
    any of them
}