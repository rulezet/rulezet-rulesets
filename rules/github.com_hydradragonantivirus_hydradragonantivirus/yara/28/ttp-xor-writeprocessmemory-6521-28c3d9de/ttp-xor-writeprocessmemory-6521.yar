rule TTP_XOR_WriteProcessMemory_6521 {
  strings:
    $key_6521 = { 32 53 [2] 00 71 [2] 06 44 [2] 28 44 [2] 17 58 }

  condition:
    any of them
}