rule TTP_XOR_WriteProcessMemory_3516 {
  strings:
    $key_3516 = { 62 64 [2] 50 46 [2] 56 73 [2] 78 73 [2] 47 6f }

  condition:
    any of them
}