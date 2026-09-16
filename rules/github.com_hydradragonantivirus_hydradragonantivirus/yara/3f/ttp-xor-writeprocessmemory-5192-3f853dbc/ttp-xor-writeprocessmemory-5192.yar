rule TTP_XOR_WriteProcessMemory_5192 {
  strings:
    $key_5192 = { 06 e0 [2] 34 c2 [2] 32 f7 [2] 1c f7 [2] 23 eb }

  condition:
    any of them
}