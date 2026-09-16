rule TTP_XOR_WriteProcessMemory_2365 {
  strings:
    $key_2365 = { 74 17 [2] 46 35 [2] 40 00 [2] 6e 00 [2] 51 1c }

  condition:
    any of them
}