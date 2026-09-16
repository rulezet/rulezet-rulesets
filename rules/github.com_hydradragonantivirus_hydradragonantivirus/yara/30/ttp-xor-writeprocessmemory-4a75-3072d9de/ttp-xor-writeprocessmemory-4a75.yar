rule TTP_XOR_WriteProcessMemory_4a75 {
  strings:
    $key_4a75 = { 1d 07 [2] 2f 25 [2] 29 10 [2] 07 10 [2] 38 0c }

  condition:
    any of them
}