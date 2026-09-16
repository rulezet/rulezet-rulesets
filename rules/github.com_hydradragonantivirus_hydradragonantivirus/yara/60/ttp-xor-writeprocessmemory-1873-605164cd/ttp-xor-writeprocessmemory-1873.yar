rule TTP_XOR_WriteProcessMemory_1873 {
  strings:
    $key_1873 = { 4f 01 [2] 7d 23 [2] 7b 16 [2] 55 16 [2] 6a 0a }

  condition:
    any of them
}