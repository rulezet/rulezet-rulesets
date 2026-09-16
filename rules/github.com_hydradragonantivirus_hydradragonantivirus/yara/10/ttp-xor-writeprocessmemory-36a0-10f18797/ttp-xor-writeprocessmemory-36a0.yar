rule TTP_XOR_WriteProcessMemory_36a0 {
  strings:
    $key_36a0 = { 61 d2 [2] 53 f0 [2] 55 c5 [2] 7b c5 [2] 44 d9 }

  condition:
    any of them
}