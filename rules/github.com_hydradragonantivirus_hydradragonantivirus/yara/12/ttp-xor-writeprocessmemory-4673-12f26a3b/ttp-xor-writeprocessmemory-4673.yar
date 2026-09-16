rule TTP_XOR_WriteProcessMemory_4673 {
  strings:
    $key_4673 = { 11 01 [2] 23 23 [2] 25 16 [2] 0b 16 [2] 34 0a }

  condition:
    any of them
}