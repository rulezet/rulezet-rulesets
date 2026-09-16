rule TTP_XOR_WriteProcessMemory_18c5 {
  strings:
    $key_18c5 = { 4f b7 [2] 7d 95 [2] 7b a0 [2] 55 a0 [2] 6a bc }

  condition:
    any of them
}