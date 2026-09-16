rule TTP_XOR_WriteProcessMemory_4477 {
  strings:
    $key_4477 = { 13 05 [2] 21 27 [2] 27 12 [2] 09 12 [2] 36 0e }

  condition:
    any of them
}