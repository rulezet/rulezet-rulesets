rule TTP_XOR_WriteProcessMemory_1d64 {
  strings:
    $key_1d64 = { 4a 16 [2] 78 34 [2] 7e 01 [2] 50 01 [2] 6f 1d }

  condition:
    any of them
}