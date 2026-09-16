rule TTP_XOR_WriteProcessMemory_26d0 {
  strings:
    $key_26d0 = { 71 a2 [2] 43 80 [2] 45 b5 [2] 6b b5 [2] 54 a9 }

  condition:
    any of them
}