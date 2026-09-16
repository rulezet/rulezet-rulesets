rule TTP_XOR_WriteProcessMemory_1b50 {
  strings:
    $key_1b50 = { 4c 22 [2] 7e 00 [2] 78 35 [2] 56 35 [2] 69 29 }

  condition:
    any of them
}