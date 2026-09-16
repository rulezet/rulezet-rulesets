rule TTP_XOR_WriteProcessMemory_5fd5 {
  strings:
    $key_5fd5 = { 08 a7 [2] 3a 85 [2] 3c b0 [2] 12 b0 [2] 2d ac }

  condition:
    any of them
}