rule TTP_XOR_WriteProcessMemory_2e16 {
  strings:
    $key_2e16 = { 79 64 [2] 4b 46 [2] 4d 73 [2] 63 73 [2] 5c 6f }

  condition:
    any of them
}