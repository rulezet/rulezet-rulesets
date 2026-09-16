rule TTP_XOR_WriteProcessMemory_0092 {
  strings:
    $key_0092 = { 57 e0 [2] 65 c2 [2] 63 f7 [2] 4d f7 [2] 72 eb }

  condition:
    any of them
}