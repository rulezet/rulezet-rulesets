rule TTP_XOR_WriteProcessMemory_61d4 {
  strings:
    $key_61d4 = { 36 a6 [2] 04 84 [2] 02 b1 [2] 2c b1 [2] 13 ad }

  condition:
    any of them
}