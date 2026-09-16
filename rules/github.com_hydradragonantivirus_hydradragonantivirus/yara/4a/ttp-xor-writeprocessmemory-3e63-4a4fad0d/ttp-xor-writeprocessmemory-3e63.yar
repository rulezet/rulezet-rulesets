rule TTP_XOR_WriteProcessMemory_3e63 {
  strings:
    $key_3e63 = { 69 11 [2] 5b 33 [2] 5d 06 [2] 73 06 [2] 4c 1a }

  condition:
    any of them
}