rule TTP_XOR_WriteProcessMemory_5174 {
  strings:
    $key_5174 = { 06 06 [2] 34 24 [2] 32 11 [2] 1c 11 [2] 23 0d }

  condition:
    any of them
}