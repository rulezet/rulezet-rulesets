rule TTP_XOR_WriteProcessMemory_0bc1 {
  strings:
    $key_0bc1 = { 5c b3 [2] 6e 91 [2] 68 a4 [2] 46 a4 [2] 79 b8 }

  condition:
    any of them
}