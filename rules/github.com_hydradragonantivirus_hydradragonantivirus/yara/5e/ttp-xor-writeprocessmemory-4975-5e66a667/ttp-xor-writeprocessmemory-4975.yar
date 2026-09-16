rule TTP_XOR_WriteProcessMemory_4975 {
  strings:
    $key_4975 = { 1e 07 [2] 2c 25 [2] 2a 10 [2] 04 10 [2] 3b 0c }

  condition:
    any of them
}