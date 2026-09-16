rule TTP_XOR_WriteProcessMemory_6dc2 {
  strings:
    $key_6dc2 = { 3a b0 [2] 08 92 [2] 0e a7 [2] 20 a7 [2] 1f bb }

  condition:
    any of them
}