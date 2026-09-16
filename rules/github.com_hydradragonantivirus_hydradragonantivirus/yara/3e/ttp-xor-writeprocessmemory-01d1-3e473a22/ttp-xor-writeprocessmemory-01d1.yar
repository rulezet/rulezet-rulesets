rule TTP_XOR_WriteProcessMemory_01d1 {
  strings:
    $key_01d1 = { 56 a3 [2] 64 81 [2] 62 b4 [2] 4c b4 [2] 73 a8 }

  condition:
    any of them
}