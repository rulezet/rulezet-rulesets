rule TTP_XOR_WriteProcessMemory_7292 {
  strings:
    $key_7292 = { 25 e0 [2] 17 c2 [2] 11 f7 [2] 3f f7 [2] 00 eb }

  condition:
    any of them
}