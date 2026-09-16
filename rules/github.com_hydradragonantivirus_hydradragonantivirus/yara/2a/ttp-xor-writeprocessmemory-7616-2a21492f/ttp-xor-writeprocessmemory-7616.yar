rule TTP_XOR_WriteProcessMemory_7616 {
  strings:
    $key_7616 = { 21 64 [2] 13 46 [2] 15 73 [2] 3b 73 [2] 04 6f }

  condition:
    any of them
}