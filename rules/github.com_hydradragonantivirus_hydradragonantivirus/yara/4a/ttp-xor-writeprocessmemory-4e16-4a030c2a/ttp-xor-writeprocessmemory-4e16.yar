rule TTP_XOR_WriteProcessMemory_4e16 {
  strings:
    $key_4e16 = { 19 64 [2] 2b 46 [2] 2d 73 [2] 03 73 [2] 3c 6f }

  condition:
    any of them
}