rule TTP_XOR_WriteProcessMemory_5dc2 {
  strings:
    $key_5dc2 = { 0a b0 [2] 38 92 [2] 3e a7 [2] 10 a7 [2] 2f bb }

  condition:
    any of them
}