rule TTP_XOR_WriteProcessMemory_7fd4 {
  strings:
    $key_7fd4 = { 28 a6 [2] 1a 84 [2] 1c b1 [2] 32 b1 [2] 0d ad }

  condition:
    any of them
}