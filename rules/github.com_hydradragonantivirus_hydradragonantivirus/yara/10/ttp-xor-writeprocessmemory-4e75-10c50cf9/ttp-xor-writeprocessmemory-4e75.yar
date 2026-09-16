rule TTP_XOR_WriteProcessMemory_4e75 {
  strings:
    $key_4e75 = { 19 07 [2] 2b 25 [2] 2d 10 [2] 03 10 [2] 3c 0c }

  condition:
    any of them
}