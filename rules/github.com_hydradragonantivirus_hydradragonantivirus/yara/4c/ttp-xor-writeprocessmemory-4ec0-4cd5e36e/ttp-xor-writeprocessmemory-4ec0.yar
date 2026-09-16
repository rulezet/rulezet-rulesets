rule TTP_XOR_WriteProcessMemory_4ec0 {
  strings:
    $key_4ec0 = { 19 b2 [2] 2b 90 [2] 2d a5 [2] 03 a5 [2] 3c b9 }

  condition:
    any of them
}