rule TTP_XOR_WriteProcessMemory_6630 {
  strings:
    $key_6630 = { 31 42 [2] 03 60 [2] 05 55 [2] 2b 55 [2] 14 49 }

  condition:
    any of them
}