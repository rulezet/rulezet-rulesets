rule TTP_XOR_WriteProcessMemory_1cc2 {
  strings:
    $key_1cc2 = { 4b b0 [2] 79 92 [2] 7f a7 [2] 51 a7 [2] 6e bb }

  condition:
    any of them
}