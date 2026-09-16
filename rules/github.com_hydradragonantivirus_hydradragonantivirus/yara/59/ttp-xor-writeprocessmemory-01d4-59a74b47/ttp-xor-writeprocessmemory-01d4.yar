rule TTP_XOR_WriteProcessMemory_01d4 {
  strings:
    $key_01d4 = { 56 a6 [2] 64 84 [2] 62 b1 [2] 4c b1 [2] 73 ad }

  condition:
    any of them
}