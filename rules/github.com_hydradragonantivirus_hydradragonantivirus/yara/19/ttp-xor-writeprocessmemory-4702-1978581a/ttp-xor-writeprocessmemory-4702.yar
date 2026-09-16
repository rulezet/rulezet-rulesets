rule TTP_XOR_WriteProcessMemory_4702 {
  strings:
    $key_4702 = { 10 70 [2] 22 52 [2] 24 67 [2] 0a 67 [2] 35 7b }

  condition:
    any of them
}