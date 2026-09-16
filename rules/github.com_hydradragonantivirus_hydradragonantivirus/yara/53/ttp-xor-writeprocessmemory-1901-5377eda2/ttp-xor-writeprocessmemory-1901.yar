rule TTP_XOR_WriteProcessMemory_1901 {
  strings:
    $key_1901 = { 4e 73 [2] 7c 51 [2] 7a 64 [2] 54 64 [2] 6b 78 }

  condition:
    any of them
}