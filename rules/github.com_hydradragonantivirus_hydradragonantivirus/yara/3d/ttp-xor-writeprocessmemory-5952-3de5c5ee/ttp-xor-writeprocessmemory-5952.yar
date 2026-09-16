rule TTP_XOR_WriteProcessMemory_5952 {
  strings:
    $key_5952 = { 0e 20 [2] 3c 02 [2] 3a 37 [2] 14 37 [2] 2b 2b }

  condition:
    any of them
}