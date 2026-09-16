rule TTP_XOR_WriteProcessMemory_0b32 {
  strings:
    $key_0b32 = { 5c 40 [2] 6e 62 [2] 68 57 [2] 46 57 [2] 79 4b }

  condition:
    any of them
}