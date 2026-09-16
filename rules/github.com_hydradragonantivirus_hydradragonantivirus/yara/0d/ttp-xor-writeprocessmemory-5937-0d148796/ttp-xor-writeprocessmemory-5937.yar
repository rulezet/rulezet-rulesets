rule TTP_XOR_WriteProcessMemory_5937 {
  strings:
    $key_5937 = { 0e 45 [2] 3c 67 [2] 3a 52 [2] 14 52 [2] 2b 4e }

  condition:
    any of them
}