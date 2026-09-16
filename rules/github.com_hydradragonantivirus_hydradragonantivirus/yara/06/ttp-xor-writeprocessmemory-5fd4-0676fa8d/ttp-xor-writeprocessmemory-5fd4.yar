rule TTP_XOR_WriteProcessMemory_5fd4 {
  strings:
    $key_5fd4 = { 08 a6 [2] 3a 84 [2] 3c b1 [2] 12 b1 [2] 2d ad }

  condition:
    any of them
}