rule TTP_XOR_WriteProcessMemory_4a70 {
  strings:
    $key_4a70 = { 1d 02 [2] 2f 20 [2] 29 15 [2] 07 15 [2] 38 09 }

  condition:
    any of them
}