rule TTP_XOR_WriteProcessMemory_7e65 {
  strings:
    $key_7e65 = { 29 17 [2] 1b 35 [2] 1d 00 [2] 33 00 [2] 0c 1c }

  condition:
    any of them
}