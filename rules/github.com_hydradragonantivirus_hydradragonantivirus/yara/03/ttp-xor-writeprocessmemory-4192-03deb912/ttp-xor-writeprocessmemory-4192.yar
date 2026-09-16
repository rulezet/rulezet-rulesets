rule TTP_XOR_WriteProcessMemory_4192 {
  strings:
    $key_4192 = { 16 e0 [2] 24 c2 [2] 22 f7 [2] 0c f7 [2] 33 eb }

  condition:
    any of them
}