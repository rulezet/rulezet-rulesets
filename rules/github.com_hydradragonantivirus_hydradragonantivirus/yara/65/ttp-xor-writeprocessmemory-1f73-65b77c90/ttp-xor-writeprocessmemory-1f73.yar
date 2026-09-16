rule TTP_XOR_WriteProcessMemory_1f73 {
  strings:
    $key_1f73 = { 48 01 [2] 7a 23 [2] 7c 16 [2] 52 16 [2] 6d 0a }

  condition:
    any of them
}