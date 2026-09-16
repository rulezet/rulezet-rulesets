rule TTP_XOR_WriteProcessMemory_1716 {
  strings:
    $key_1716 = { 40 64 [2] 72 46 [2] 74 73 [2] 5a 73 [2] 65 6f }

  condition:
    any of them
}