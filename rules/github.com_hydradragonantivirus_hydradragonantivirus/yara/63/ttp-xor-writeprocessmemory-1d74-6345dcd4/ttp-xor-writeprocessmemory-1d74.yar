rule TTP_XOR_WriteProcessMemory_1d74 {
  strings:
    $key_1d74 = { 4a 06 [2] 78 24 [2] 7e 11 [2] 50 11 [2] 6f 0d }

  condition:
    any of them
}