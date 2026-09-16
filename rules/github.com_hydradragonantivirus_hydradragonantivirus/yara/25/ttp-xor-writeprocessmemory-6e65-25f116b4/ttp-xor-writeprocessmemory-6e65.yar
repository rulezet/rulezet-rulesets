rule TTP_XOR_WriteProcessMemory_6e65 {
  strings:
    $key_6e65 = { 39 17 [2] 0b 35 [2] 0d 00 [2] 23 00 [2] 1c 1c }

  condition:
    any of them
}