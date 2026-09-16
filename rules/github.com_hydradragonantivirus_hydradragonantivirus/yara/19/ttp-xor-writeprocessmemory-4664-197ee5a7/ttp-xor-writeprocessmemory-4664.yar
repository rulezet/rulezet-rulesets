rule TTP_XOR_WriteProcessMemory_4664 {
  strings:
    $key_4664 = { 11 16 [2] 23 34 [2] 25 01 [2] 0b 01 [2] 34 1d }

  condition:
    any of them
}