rule TTP_XOR_WriteProcessMemory_7664 {
  strings:
    $key_7664 = { 21 16 [2] 13 34 [2] 15 01 [2] 3b 01 [2] 04 1d }

  condition:
    any of them
}