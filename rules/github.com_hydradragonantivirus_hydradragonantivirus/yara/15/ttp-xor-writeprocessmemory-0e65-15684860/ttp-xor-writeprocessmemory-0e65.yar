rule TTP_XOR_WriteProcessMemory_0e65 {
  strings:
    $key_0e65 = { 59 17 [2] 6b 35 [2] 6d 00 [2] 43 00 [2] 7c 1c }

  condition:
    any of them
}