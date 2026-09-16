rule TTP_XOR_WriteProcessMemory_6652 {
  strings:
    $key_6652 = { 31 20 [2] 03 02 [2] 05 37 [2] 2b 37 [2] 14 2b }

  condition:
    any of them
}