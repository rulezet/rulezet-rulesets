rule TTP_XOR_WriteProcessMemory_1865 {
  strings:
    $key_1865 = { 4f 17 [2] 7d 35 [2] 7b 00 [2] 55 00 [2] 6a 1c }

  condition:
    any of them
}