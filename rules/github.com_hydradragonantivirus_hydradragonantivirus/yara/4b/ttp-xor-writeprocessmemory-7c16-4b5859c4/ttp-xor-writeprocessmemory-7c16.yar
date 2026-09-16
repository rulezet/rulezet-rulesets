rule TTP_XOR_WriteProcessMemory_7c16 {
  strings:
    $key_7c16 = { 2b 64 [2] 19 46 [2] 1f 73 [2] 31 73 [2] 0e 6f }

  condition:
    any of them
}