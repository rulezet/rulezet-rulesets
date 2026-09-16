rule TTP_XOR_WriteProcessMemory_4092 {
  strings:
    $key_4092 = { 17 e0 [2] 25 c2 [2] 23 f7 [2] 0d f7 [2] 32 eb }

  condition:
    any of them
}