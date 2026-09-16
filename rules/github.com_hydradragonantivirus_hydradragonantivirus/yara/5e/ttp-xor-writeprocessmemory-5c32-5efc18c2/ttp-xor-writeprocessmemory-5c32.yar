rule TTP_XOR_WriteProcessMemory_5c32 {
  strings:
    $key_5c32 = { 0b 40 [2] 39 62 [2] 3f 57 [2] 11 57 [2] 2e 4b }

  condition:
    any of them
}