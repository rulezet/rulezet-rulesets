rule TTP_XOR_WriteProcessMemory_1d75 {
  strings:
    $key_1d75 = { 4a 07 [2] 78 25 [2] 7e 10 [2] 50 10 [2] 6f 0c }

  condition:
    any of them
}