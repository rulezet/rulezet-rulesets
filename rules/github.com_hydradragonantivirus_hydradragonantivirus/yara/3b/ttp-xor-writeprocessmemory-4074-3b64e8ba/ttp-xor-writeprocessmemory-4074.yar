rule TTP_XOR_WriteProcessMemory_4074 {
  strings:
    $key_4074 = { 17 06 [2] 25 24 [2] 23 11 [2] 0d 11 [2] 32 0d }

  condition:
    any of them
}