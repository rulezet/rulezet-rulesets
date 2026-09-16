rule TTP_XOR_WriteProcessMemory_5052 {
  strings:
    $key_5052 = { 07 20 [2] 35 02 [2] 33 37 [2] 1d 37 [2] 22 2b }

  condition:
    any of them
}