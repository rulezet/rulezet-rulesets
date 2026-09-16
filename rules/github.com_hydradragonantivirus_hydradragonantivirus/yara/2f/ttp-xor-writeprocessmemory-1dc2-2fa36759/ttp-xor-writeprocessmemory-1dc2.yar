rule TTP_XOR_WriteProcessMemory_1dc2 {
  strings:
    $key_1dc2 = { 4a b0 [2] 78 92 [2] 7e a7 [2] 50 a7 [2] 6f bb }

  condition:
    any of them
}