rule TTP_XOR_WriteProcessMemory_4a25 {
  strings:
    $key_4a25 = { 1d 57 [2] 2f 75 [2] 29 40 [2] 07 40 [2] 38 5c }

  condition:
    any of them
}