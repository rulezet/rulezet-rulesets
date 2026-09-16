rule TTP_XOR_WriteProcessMemory_5923 {
  strings:
    $key_5923 = { 0e 51 [2] 3c 73 [2] 3a 46 [2] 14 46 [2] 2b 5a }

  condition:
    any of them
}