rule TTP_XOR_WriteProcessMemory_2f16 {
  strings:
    $key_2f16 = { 78 64 [2] 4a 46 [2] 4c 73 [2] 62 73 [2] 5d 6f }

  condition:
    any of them
}