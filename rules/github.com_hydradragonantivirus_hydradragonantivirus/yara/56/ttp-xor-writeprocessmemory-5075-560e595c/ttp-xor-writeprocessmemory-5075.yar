rule TTP_XOR_WriteProcessMemory_5075 {
  strings:
    $key_5075 = { 07 07 [2] 35 25 [2] 33 10 [2] 1d 10 [2] 22 0c }

  condition:
    any of them
}