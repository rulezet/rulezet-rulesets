rule TTP_XOR_WriteProcessMemory_ea16 {
  strings:
    $key_ea16 = { bd 64 [2] 8f 46 [2] 89 73 [2] a7 73 [2] 98 6f }

  condition:
    any of them
}