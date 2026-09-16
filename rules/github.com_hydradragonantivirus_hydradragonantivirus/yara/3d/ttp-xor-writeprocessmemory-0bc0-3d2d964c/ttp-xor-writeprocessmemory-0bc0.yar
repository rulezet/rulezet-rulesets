rule TTP_XOR_WriteProcessMemory_0bc0 {
  strings:
    $key_0bc0 = { 5c b2 [2] 6e 90 [2] 68 a5 [2] 46 a5 [2] 79 b9 }

  condition:
    any of them
}