rule TTP_XOR_WriteProcessMemory_3416 {
  strings:
    $key_3416 = { 63 64 [2] 51 46 [2] 57 73 [2] 79 73 [2] 46 6f }

  condition:
    any of them
}