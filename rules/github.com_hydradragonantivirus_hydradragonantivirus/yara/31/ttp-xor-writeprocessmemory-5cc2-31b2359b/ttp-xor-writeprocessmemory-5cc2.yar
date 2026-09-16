rule TTP_XOR_WriteProcessMemory_5cc2 {
  strings:
    $key_5cc2 = { 0b b0 [2] 39 92 [2] 3f a7 [2] 11 a7 [2] 2e bb }

  condition:
    any of them
}