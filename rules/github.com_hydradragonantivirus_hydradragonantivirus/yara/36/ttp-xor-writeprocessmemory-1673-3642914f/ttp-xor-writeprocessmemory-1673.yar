rule TTP_XOR_WriteProcessMemory_1673 {
  strings:
    $key_1673 = { 41 01 [2] 73 23 [2] 75 16 [2] 5b 16 [2] 64 0a }

  condition:
    any of them
}