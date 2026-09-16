rule TTP_XOR_WriteProcessMemory_7e25 {
  strings:
    $key_7e25 = { 29 57 [2] 1b 75 [2] 1d 40 [2] 33 40 [2] 0c 5c }

  condition:
    any of them
}