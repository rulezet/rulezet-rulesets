rule TTP_XOR_WriteProcessMemory_0773 {
  strings:
    $key_0773 = { 50 01 [2] 62 23 [2] 64 16 [2] 4a 16 [2] 75 0a }

  condition:
    any of them
}