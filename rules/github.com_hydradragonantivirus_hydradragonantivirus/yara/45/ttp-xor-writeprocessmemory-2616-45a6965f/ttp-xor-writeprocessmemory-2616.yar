rule TTP_XOR_WriteProcessMemory_2616 {
  strings:
    $key_2616 = { 71 64 [2] 43 46 [2] 45 73 [2] 6b 73 [2] 54 6f }

  condition:
    any of them
}