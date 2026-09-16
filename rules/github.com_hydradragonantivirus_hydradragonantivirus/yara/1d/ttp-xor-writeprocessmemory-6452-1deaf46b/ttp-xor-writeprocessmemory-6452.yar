rule TTP_XOR_WriteProcessMemory_6452 {
  strings:
    $key_6452 = { 33 20 [2] 01 02 [2] 07 37 [2] 29 37 [2] 16 2b }

  condition:
    any of them
}