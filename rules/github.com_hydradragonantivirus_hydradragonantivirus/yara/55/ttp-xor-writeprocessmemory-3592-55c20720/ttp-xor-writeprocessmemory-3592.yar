rule TTP_XOR_WriteProcessMemory_3592 {
  strings:
    $key_3592 = { 62 e0 [2] 50 c2 [2] 56 f7 [2] 78 f7 [2] 47 eb }

  condition:
    any of them
}