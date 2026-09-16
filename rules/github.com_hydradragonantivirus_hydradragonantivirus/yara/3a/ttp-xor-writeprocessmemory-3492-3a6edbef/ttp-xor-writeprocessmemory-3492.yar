rule TTP_XOR_WriteProcessMemory_3492 {
  strings:
    $key_3492 = { 63 e0 [2] 51 c2 [2] 57 f7 [2] 79 f7 [2] 46 eb }

  condition:
    any of them
}