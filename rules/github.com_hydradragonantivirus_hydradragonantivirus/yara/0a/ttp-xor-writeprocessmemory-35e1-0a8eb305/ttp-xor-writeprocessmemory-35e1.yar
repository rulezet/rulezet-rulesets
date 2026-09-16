rule TTP_XOR_WriteProcessMemory_35e1 {
  strings:
    $key_35e1 = { 62 93 [2] 50 b1 [2] 56 84 [2] 78 84 [2] 47 98 }

  condition:
    any of them
}