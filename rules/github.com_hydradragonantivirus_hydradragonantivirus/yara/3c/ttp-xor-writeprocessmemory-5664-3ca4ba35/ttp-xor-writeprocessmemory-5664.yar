rule TTP_XOR_WriteProcessMemory_5664 {
  strings:
    $key_5664 = { 01 16 [2] 33 34 [2] 35 01 [2] 1b 01 [2] 24 1d }

  condition:
    any of them
}