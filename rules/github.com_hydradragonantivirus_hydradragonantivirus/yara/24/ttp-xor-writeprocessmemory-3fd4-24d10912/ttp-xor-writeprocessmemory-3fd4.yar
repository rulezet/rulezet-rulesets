rule TTP_XOR_WriteProcessMemory_3fd4 {
  strings:
    $key_3fd4 = { 68 a6 [2] 5a 84 [2] 5c b1 [2] 72 b1 [2] 4d ad }

  condition:
    any of them
}