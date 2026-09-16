rule TTP_XOR_WriteProcessMemory_1d02 {
  strings:
    $key_1d02 = { 4a 70 [2] 78 52 [2] 7e 67 [2] 50 67 [2] 6f 7b }

  condition:
    any of them
}