rule TTP_XOR_WriteProcessMemory_4461 {
  strings:
    $key_4461 = { 13 13 [2] 21 31 [2] 27 04 [2] 09 04 [2] 36 18 }

  condition:
    any of them
}