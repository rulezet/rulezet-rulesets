rule TTP_XOR_WriteProcessMemory_4464 {
  strings:
    $key_4464 = { 13 16 [2] 21 34 [2] 27 01 [2] 09 01 [2] 36 1d }

  condition:
    any of them
}