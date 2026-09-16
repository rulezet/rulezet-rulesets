rule TTP_XOR_WriteProcessMemory_6e06 {
  strings:
    $key_6e06 = { 39 74 [2] 0b 56 [2] 0d 63 [2] 23 63 [2] 1c 7f }

  condition:
    any of them
}