rule TTP_XOR_WriteProcessMemory_5116 {
  strings:
    $key_5116 = { 06 64 [2] 34 46 [2] 32 73 [2] 1c 73 [2] 23 6f }

  condition:
    any of them
}