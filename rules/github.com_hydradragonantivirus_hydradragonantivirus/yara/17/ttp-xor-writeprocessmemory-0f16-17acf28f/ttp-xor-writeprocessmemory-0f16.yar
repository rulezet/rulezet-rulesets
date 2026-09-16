rule TTP_XOR_WriteProcessMemory_0f16 {
  strings:
    $key_0f16 = { 58 64 [2] 6a 46 [2] 6c 73 [2] 42 73 [2] 7d 6f }

  condition:
    any of them
}