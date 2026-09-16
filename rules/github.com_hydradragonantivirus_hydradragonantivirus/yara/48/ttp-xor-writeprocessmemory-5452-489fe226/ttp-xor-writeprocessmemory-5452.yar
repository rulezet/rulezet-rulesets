rule TTP_XOR_WriteProcessMemory_5452 {
  strings:
    $key_5452 = { 03 20 [2] 31 02 [2] 37 37 [2] 19 37 [2] 26 2b }

  condition:
    any of them
}