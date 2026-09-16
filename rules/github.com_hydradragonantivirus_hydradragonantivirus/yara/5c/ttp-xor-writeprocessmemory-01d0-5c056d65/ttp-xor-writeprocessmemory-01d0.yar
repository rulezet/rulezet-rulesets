rule TTP_XOR_WriteProcessMemory_01d0 {
  strings:
    $key_01d0 = { 56 a2 [2] 64 80 [2] 62 b5 [2] 4c b5 [2] 73 a9 }

  condition:
    any of them
}