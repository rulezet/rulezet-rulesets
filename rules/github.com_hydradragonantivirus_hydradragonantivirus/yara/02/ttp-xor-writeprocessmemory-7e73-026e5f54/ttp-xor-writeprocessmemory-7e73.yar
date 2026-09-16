rule TTP_XOR_WriteProcessMemory_7e73 {
  strings:
    $key_7e73 = { 29 01 [2] 1b 23 [2] 1d 16 [2] 33 16 [2] 0c 0a }

  condition:
    any of them
}