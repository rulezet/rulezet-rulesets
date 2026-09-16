rule TTP_XOR_WriteProcessMemory_1f16 {
  strings:
    $key_1f16 = { 48 64 [2] 7a 46 [2] 7c 73 [2] 52 73 [2] 6d 6f }

  condition:
    any of them
}