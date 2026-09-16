rule TTP_XOR_WriteProcessMemory_7552 {
  strings:
    $key_7552 = { 22 20 [2] 10 02 [2] 16 37 [2] 38 37 [2] 07 2b }

  condition:
    any of them
}