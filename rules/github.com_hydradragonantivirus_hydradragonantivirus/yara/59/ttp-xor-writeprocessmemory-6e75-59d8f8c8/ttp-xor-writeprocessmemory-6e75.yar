rule TTP_XOR_WriteProcessMemory_6e75 {
  strings:
    $key_6e75 = { 39 07 [2] 0b 25 [2] 0d 10 [2] 23 10 [2] 1c 0c }

  condition:
    any of them
}