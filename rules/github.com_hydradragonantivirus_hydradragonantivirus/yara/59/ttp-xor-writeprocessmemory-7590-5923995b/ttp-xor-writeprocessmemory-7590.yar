rule TTP_XOR_WriteProcessMemory_7590 {
  strings:
    $key_7590 = { 22 e2 [2] 10 c0 [2] 16 f5 [2] 38 f5 [2] 07 e9 }

  condition:
    any of them
}