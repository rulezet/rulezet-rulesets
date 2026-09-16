rule TTP_XOR_WriteProcessMemory_2ed5 {
  strings:
    $key_2ed5 = { 79 a7 [2] 4b 85 [2] 4d b0 [2] 63 b0 [2] 5c ac }

  condition:
    any of them
}