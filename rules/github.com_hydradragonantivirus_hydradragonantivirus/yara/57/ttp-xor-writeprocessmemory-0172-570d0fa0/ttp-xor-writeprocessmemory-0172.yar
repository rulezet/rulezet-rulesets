rule TTP_XOR_WriteProcessMemory_0172 {
  strings:
    $key_0172 = { 56 00 [2] 64 22 [2] 62 17 [2] 4c 17 [2] 73 0b }

  condition:
    any of them
}