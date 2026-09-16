rule TTP_XOR_WriteProcessMemory_1916 {
  strings:
    $key_1916 = { 4e 64 [2] 7c 46 [2] 7a 73 [2] 54 73 [2] 6b 6f }

  condition:
    any of them
}