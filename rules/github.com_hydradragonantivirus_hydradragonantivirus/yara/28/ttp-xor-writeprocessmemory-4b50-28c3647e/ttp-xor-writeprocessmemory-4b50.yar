rule TTP_XOR_WriteProcessMemory_4b50 {
  strings:
    $key_4b50 = { 1c 22 [2] 2e 00 [2] 28 35 [2] 06 35 [2] 39 29 }

  condition:
    any of them
}