rule TTP_XOR_WriteProcessMemory_7592 {
  strings:
    $key_7592 = { 22 e0 [2] 10 c2 [2] 16 f7 [2] 38 f7 [2] 07 eb }

  condition:
    any of them
}