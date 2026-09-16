rule TTP_XOR_WriteProcessMemory_3f16 {
  strings:
    $key_3f16 = { 68 64 [2] 5a 46 [2] 5c 73 [2] 72 73 [2] 4d 6f }

  condition:
    any of them
}