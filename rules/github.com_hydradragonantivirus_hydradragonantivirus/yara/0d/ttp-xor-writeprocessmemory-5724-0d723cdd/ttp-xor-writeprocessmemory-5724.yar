rule TTP_XOR_WriteProcessMemory_5724 {
  strings:
    $key_5724 = { 00 56 [2] 32 74 [2] 34 41 [2] 1a 41 [2] 25 5d }

  condition:
    any of them
}