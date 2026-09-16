rule TTP_XOR_WriteProcessMemory_6616 {
  strings:
    $key_6616 = { 31 64 [2] 03 46 [2] 05 73 [2] 2b 73 [2] 14 6f }

  condition:
    any of them
}