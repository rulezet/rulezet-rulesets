rule TTP_XOR_WriteProcessMemory_0490 {
  strings:
    $key_0490 = { 53 e2 [2] 61 c0 [2] 67 f5 [2] 49 f5 [2] 76 e9 }

  condition:
    any of them
}