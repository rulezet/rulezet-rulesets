rule TTP_XOR_WriteProcessMemory_6590 {
  strings:
    $key_6590 = { 32 e2 [2] 00 c0 [2] 06 f5 [2] 28 f5 [2] 17 e9 }

  condition:
    any of them
}