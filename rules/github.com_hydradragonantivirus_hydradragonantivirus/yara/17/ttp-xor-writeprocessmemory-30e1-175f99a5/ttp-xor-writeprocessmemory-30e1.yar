rule TTP_XOR_WriteProcessMemory_30e1 {
  strings:
    $key_30e1 = { 67 93 [2] 55 b1 [2] 53 84 [2] 7d 84 [2] 42 98 }

  condition:
    any of them
}