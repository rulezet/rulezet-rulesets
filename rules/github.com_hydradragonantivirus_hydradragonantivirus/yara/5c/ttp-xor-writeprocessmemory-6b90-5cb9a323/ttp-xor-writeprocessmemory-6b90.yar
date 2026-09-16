rule TTP_XOR_WriteProcessMemory_6b90 {
  strings:
    $key_6b90 = { 3c e2 [2] 0e c0 [2] 08 f5 [2] 26 f5 [2] 19 e9 }

  condition:
    any of them
}