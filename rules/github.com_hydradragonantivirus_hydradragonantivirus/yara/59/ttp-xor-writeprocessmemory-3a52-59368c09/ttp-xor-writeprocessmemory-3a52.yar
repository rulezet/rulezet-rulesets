rule TTP_XOR_WriteProcessMemory_3a52 {
  strings:
    $key_3a52 = { 6d 20 [2] 5f 02 [2] 59 37 [2] 77 37 [2] 48 2b }

  condition:
    any of them
}