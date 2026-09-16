rule TTP_XOR_WriteProcessMemory_2392 {
  strings:
    $key_2392 = { 74 e0 [2] 46 c2 [2] 40 f7 [2] 6e f7 [2] 51 eb }

  condition:
    any of them
}