rule TTP_XOR_WriteProcessMemory_01d2 {
  strings:
    $key_01d2 = { 56 a0 [2] 64 82 [2] 62 b7 [2] 4c b7 [2] 73 ab }

  condition:
    any of them
}