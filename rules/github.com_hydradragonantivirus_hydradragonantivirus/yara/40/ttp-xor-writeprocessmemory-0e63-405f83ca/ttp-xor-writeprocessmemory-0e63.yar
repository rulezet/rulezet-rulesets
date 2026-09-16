rule TTP_XOR_WriteProcessMemory_0e63 {
  strings:
    $key_0e63 = { 59 11 [2] 6b 33 [2] 6d 06 [2] 43 06 [2] 7c 1a }

  condition:
    any of them
}