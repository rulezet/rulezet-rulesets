rule TTP_XOR_WriteProcessMemory_5b16 {
  strings:
    $key_5b16 = { 0c 64 [2] 3e 46 [2] 38 73 [2] 16 73 [2] 29 6f }

  condition:
    any of them
}