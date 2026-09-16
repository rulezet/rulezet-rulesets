rule TTP_XOR_WriteProcessMemory_5c21 {
  strings:
    $key_5c21 = { 0b 53 [2] 39 71 [2] 3f 44 [2] 11 44 [2] 2e 58 }

  condition:
    any of them
}