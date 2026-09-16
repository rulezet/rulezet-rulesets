rule TTP_XOR_WriteProcessMemory_5367 {
  strings:
    $key_5367 = { 04 15 [2] 36 37 [2] 30 02 [2] 1e 02 [2] 21 1e }

  condition:
    any of them
}