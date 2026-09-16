rule TTP_XOR_WriteProcessMemory_0dc2 {
  strings:
    $key_0dc2 = { 5a b0 [2] 68 92 [2] 6e a7 [2] 40 a7 [2] 7f bb }

  condition:
    any of them
}