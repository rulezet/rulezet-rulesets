rule TTP_XOR_WriteProcessMemory_e092 {
  strings:
    $key_e092 = { b7 e0 [2] 85 c2 [2] 83 f7 [2] ad f7 [2] 92 eb }

  condition:
    any of them
}