rule TTP_XOR_WriteProcessMemory_e975 {
  strings:
    $key_e975 = { be 07 [2] 8c 25 [2] 8a 10 [2] a4 10 [2] 9b 0c }

  condition:
    any of them
}