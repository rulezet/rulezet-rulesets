rule TTP_XOR_WriteProcessMemory_5616 {
  strings:
    $key_5616 = { 01 64 [2] 33 46 [2] 35 73 [2] 1b 73 [2] 24 6f }

  condition:
    any of them
}