rule TTP_XOR_WriteProcessMemory_1316 {
  strings:
    $key_1316 = { 44 64 [2] 76 46 [2] 70 73 [2] 5e 73 [2] 61 6f }

  condition:
    any of them
}