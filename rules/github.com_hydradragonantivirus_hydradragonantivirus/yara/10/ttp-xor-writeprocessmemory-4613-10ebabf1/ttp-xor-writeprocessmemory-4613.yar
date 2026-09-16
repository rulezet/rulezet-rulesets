rule TTP_XOR_WriteProcessMemory_4613 {
  strings:
    $key_4613 = { 11 61 [2] 23 43 [2] 25 76 [2] 0b 76 [2] 34 6a }

  condition:
    any of them
}