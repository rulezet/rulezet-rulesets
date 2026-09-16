rule TTP_XOR_WriteProcessMemory_2dc2 {
  strings:
    $key_2dc2 = { 7a b0 [2] 48 92 [2] 4e a7 [2] 60 a7 [2] 5f bb }

  condition:
    any of them
}