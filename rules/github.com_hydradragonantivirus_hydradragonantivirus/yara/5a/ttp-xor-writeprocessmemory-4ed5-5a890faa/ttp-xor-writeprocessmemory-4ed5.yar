rule TTP_XOR_WriteProcessMemory_4ed5 {
  strings:
    $key_4ed5 = { 19 a7 [2] 2b 85 [2] 2d b0 [2] 03 b0 [2] 3c ac }

  condition:
    any of them
}