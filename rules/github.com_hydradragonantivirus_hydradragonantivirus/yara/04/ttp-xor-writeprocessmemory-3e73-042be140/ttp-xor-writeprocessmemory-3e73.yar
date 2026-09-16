rule TTP_XOR_WriteProcessMemory_3e73 {
  strings:
    $key_3e73 = { 69 01 [2] 5b 23 [2] 5d 16 [2] 73 16 [2] 4c 0a }

  condition:
    any of them
}