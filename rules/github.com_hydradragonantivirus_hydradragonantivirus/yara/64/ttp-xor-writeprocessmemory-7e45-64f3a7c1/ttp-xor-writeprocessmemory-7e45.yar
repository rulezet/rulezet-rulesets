rule TTP_XOR_WriteProcessMemory_7e45 {
  strings:
    $key_7e45 = { 29 37 [2] 1b 15 [2] 1d 20 [2] 33 20 [2] 0c 3c }

  condition:
    any of them
}