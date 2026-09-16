rule TTP_XOR_WriteProcessMemory_61d0 {
  strings:
    $key_61d0 = { 36 a2 [2] 04 80 [2] 02 b5 [2] 2c b5 [2] 13 a9 }

  condition:
    any of them
}