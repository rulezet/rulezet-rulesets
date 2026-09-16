rule TTP_XOR_WriteProcessMemory_5933 {
  strings:
    $key_5933 = { 0e 41 [2] 3c 63 [2] 3a 56 [2] 14 56 [2] 2b 4a }

  condition:
    any of them
}