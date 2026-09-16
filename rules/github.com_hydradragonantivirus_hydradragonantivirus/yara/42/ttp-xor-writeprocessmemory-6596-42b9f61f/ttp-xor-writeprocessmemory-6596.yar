rule TTP_XOR_WriteProcessMemory_6596 {
  strings:
    $key_6596 = { 32 e4 [2] 00 c6 [2] 06 f3 [2] 28 f3 [2] 17 ef }

  condition:
    any of them
}