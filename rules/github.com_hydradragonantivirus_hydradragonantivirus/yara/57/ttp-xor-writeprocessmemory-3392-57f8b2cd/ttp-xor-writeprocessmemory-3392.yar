rule TTP_XOR_WriteProcessMemory_3392 {
  strings:
    $key_3392 = { 64 e0 [2] 56 c2 [2] 50 f7 [2] 7e f7 [2] 41 eb }

  condition:
    any of them
}