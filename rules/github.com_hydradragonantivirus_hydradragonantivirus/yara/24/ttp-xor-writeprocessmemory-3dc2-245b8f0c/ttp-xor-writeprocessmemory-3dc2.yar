rule TTP_XOR_WriteProcessMemory_3dc2 {
  strings:
    $key_3dc2 = { 6a b0 [2] 58 92 [2] 5e a7 [2] 70 a7 [2] 4f bb }

  condition:
    any of them
}