rule TTP_XOR_WriteProcessMemory_0e06 {
  strings:
    $key_0e06 = { 59 74 [2] 6b 56 [2] 6d 63 [2] 43 63 [2] 7c 7f }

  condition:
    any of them
}