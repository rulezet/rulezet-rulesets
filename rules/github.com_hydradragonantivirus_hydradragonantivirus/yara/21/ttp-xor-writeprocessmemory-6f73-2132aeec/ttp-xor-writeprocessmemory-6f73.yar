rule TTP_XOR_WriteProcessMemory_6f73 {
  strings:
    $key_6f73 = { 38 01 [2] 0a 23 [2] 0c 16 [2] 22 16 [2] 1d 0a }

  condition:
    any of them
}