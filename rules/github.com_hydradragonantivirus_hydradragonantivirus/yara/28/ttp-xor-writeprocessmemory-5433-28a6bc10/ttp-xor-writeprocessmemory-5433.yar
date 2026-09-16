rule TTP_XOR_WriteProcessMemory_5433 {
  strings:
    $key_5433 = { 03 41 [2] 31 63 [2] 37 56 [2] 19 56 [2] 26 4a }

  condition:
    any of them
}