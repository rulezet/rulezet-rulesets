rule TTP_XOR_WriteProcessMemory_6551 {
  strings:
    $key_6551 = { 32 23 [2] 00 01 [2] 06 34 [2] 28 34 [2] 17 28 }

  condition:
    any of them
}