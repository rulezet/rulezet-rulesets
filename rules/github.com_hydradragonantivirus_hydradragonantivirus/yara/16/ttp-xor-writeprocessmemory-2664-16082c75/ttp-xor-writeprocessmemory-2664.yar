rule TTP_XOR_WriteProcessMemory_2664 {
  strings:
    $key_2664 = { 71 16 [2] 43 34 [2] 45 01 [2] 6b 01 [2] 54 1d }

  condition:
    any of them
}