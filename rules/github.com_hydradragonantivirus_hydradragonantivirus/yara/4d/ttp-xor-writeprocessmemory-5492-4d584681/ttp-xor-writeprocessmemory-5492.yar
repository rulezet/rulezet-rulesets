rule TTP_XOR_WriteProcessMemory_5492 {
  strings:
    $key_5492 = { 03 e0 [2] 31 c2 [2] 37 f7 [2] 19 f7 [2] 26 eb }

  condition:
    any of them
}