rule TTP_XOR_WriteProcessMemory_6675 {
  strings:
    $key_6675 = { 31 07 [2] 03 25 [2] 05 10 [2] 2b 10 [2] 14 0c }

  condition:
    any of them
}