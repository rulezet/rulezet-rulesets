rule TTP_XOR_WriteProcessMemory_0e25 {
  strings:
    $key_0e25 = { 59 57 [2] 6b 75 [2] 6d 40 [2] 43 40 [2] 7c 5c }

  condition:
    any of them
}