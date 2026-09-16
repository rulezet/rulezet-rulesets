rule TTP_XOR_WriteProcessMemory_1b90 {
  strings:
    $key_1b90 = { 4c e2 [2] 7e c0 [2] 78 f5 [2] 56 f5 [2] 69 e9 }

  condition:
    any of them
}