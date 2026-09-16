rule TTP_XOR_WriteProcessMemory_6113 {
  strings:
    $key_6113 = { 36 61 [2] 04 43 [2] 02 76 [2] 2c 76 [2] 13 6a }

  condition:
    any of them
}