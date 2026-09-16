rule TTP_XOR_WriteProcessMemory_6662 {
  strings:
    $key_6662 = { 31 10 [2] 03 32 [2] 05 07 [2] 2b 07 [2] 14 1b }

  condition:
    any of them
}