rule TTP_XOR_WriteProcessMemory_1640 {
  strings:
    $key_1640 = { 41 32 [2] 73 10 [2] 75 25 [2] 5b 25 [2] 64 39 }

  condition:
    any of them
}