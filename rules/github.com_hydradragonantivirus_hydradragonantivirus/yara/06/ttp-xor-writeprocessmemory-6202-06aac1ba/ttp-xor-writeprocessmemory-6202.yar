rule TTP_XOR_WriteProcessMemory_6202 {
  strings:
    $key_6202 = { 35 70 [2] 07 52 [2] 01 67 [2] 2f 67 [2] 10 7b }

  condition:
    any of them
}