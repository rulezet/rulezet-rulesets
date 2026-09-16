rule TTP_XOR_WriteProcessMemory_6f75 {
  strings:
    $key_6f75 = { 38 07 [2] 0a 25 [2] 0c 10 [2] 22 10 [2] 1d 0c }

  condition:
    any of them
}