rule TTP_XOR_WriteProcessMemory_5953 {
  strings:
    $key_5953 = { 0e 21 [2] 3c 03 [2] 3a 36 [2] 14 36 [2] 2b 2a }

  condition:
    any of them
}