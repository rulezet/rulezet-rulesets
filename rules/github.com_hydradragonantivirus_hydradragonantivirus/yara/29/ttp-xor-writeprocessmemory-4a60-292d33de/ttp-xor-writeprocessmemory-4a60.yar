rule TTP_XOR_WriteProcessMemory_4a60 {
  strings:
    $key_4a60 = { 1d 12 [2] 2f 30 [2] 29 05 [2] 07 05 [2] 38 19 }

  condition:
    any of them
}