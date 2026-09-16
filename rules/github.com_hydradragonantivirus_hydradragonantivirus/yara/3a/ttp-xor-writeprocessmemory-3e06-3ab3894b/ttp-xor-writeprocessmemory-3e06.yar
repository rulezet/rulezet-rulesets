rule TTP_XOR_WriteProcessMemory_3e06 {
  strings:
    $key_3e06 = { 69 74 [2] 5b 56 [2] 5d 63 [2] 73 63 [2] 4c 7f }

  condition:
    any of them
}