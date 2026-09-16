rule TTP_XOR_WriteProcessMemory_6572 {
  strings:
    $key_6572 = { 32 00 [2] 00 22 [2] 06 17 [2] 28 17 [2] 17 0b }

  condition:
    any of them
}