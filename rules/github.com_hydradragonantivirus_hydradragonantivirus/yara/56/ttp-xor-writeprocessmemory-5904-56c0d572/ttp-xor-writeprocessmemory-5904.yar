rule TTP_XOR_WriteProcessMemory_5904 {
  strings:
    $key_5904 = { 0e 76 [2] 3c 54 [2] 3a 61 [2] 14 61 [2] 2b 7d }

  condition:
    any of them
}