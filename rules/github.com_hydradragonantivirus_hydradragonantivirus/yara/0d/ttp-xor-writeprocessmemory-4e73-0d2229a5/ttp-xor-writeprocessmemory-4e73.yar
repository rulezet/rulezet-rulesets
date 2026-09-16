rule TTP_XOR_WriteProcessMemory_4e73 {
  strings:
    $key_4e73 = { 19 01 [2] 2b 23 [2] 2d 16 [2] 03 16 [2] 3c 0a }

  condition:
    any of them
}