rule TTP_XOR_WriteProcessMemory_1092 {
  strings:
    $key_1092 = { 47 e0 [2] 75 c2 [2] 73 f7 [2] 5d f7 [2] 62 eb }

  condition:
    any of them
}