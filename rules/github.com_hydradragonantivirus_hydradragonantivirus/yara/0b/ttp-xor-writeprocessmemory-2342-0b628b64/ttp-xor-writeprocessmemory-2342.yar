rule TTP_XOR_WriteProcessMemory_2342 {
  strings:
    $key_2342 = { 74 30 [2] 46 12 [2] 40 27 [2] 6e 27 [2] 51 3b }

  condition:
    any of them
}