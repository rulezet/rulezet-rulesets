rule TTP_XOR_WriteProcessMemory_5bc0 {
  strings:
    $key_5bc0 = { 0c b2 [2] 3e 90 [2] 38 a5 [2] 16 a5 [2] 29 b9 }

  condition:
    any of them
}