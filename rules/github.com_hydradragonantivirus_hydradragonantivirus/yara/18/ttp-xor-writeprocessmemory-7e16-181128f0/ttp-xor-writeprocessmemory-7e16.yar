rule TTP_XOR_WriteProcessMemory_7e16 {
  strings:
    $key_7e16 = { 29 64 [2] 1b 46 [2] 1d 73 [2] 33 73 [2] 0c 6f }

  condition:
    any of them
}