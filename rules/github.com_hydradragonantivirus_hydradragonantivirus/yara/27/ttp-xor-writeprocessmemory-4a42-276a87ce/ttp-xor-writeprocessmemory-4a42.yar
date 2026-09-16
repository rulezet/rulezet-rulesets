rule TTP_XOR_WriteProcessMemory_4a42 {
  strings:
    $key_4a42 = { 1d 30 [2] 2f 12 [2] 29 27 [2] 07 27 [2] 38 3b }

  condition:
    any of them
}