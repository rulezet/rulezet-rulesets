rule TTP_XOR_WriteProcessMemory_5943 {
  strings:
    $key_5943 = { 0e 31 [2] 3c 13 [2] 3a 26 [2] 14 26 [2] 2b 3a }

  condition:
    any of them
}