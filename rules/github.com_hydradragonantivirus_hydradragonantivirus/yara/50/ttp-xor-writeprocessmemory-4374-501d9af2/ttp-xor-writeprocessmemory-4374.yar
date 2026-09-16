rule TTP_XOR_WriteProcessMemory_4374 {
  strings:
    $key_4374 = { 14 06 [2] 26 24 [2] 20 11 [2] 0e 11 [2] 31 0d }

  condition:
    any of them
}