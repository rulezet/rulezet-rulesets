rule TTP_XOR_WriteProcessMemory_6585 {
  strings:
    $key_6585 = { 32 f7 [2] 00 d5 [2] 06 e0 [2] 28 e0 [2] 17 fc }

  condition:
    any of them
}