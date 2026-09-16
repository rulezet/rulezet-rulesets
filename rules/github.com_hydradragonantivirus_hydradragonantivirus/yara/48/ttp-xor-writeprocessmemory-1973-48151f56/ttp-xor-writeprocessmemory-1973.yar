rule TTP_XOR_WriteProcessMemory_1973 {
  strings:
    $key_1973 = { 4e 01 [2] 7c 23 [2] 7a 16 [2] 54 16 [2] 6b 0a }

  condition:
    any of them
}