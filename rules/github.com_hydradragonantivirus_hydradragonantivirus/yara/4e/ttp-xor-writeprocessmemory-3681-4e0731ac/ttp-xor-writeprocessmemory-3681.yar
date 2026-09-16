rule TTP_XOR_WriteProcessMemory_3681 {
  strings:
    $key_3681 = { 61 f3 [2] 53 d1 [2] 55 e4 [2] 7b e4 [2] 44 f8 }

  condition:
    any of them
}