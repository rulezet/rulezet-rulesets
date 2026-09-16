rule TTP_XOR_WriteProcessMemory_5352 {
  strings:
    $key_5352 = { 04 20 [2] 36 02 [2] 30 37 [2] 1e 37 [2] 21 2b }

  condition:
    any of them
}