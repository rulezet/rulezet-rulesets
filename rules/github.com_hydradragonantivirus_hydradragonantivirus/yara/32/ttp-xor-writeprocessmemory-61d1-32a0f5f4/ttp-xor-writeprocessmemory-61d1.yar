rule TTP_XOR_WriteProcessMemory_61d1 {
  strings:
    $key_61d1 = { 36 a3 [2] 04 81 [2] 02 b4 [2] 2c b4 [2] 13 a8 }

  condition:
    any of them
}