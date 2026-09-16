rule TTP_XOR_WriteProcessMemory_7371 {
  strings:
    $key_7371 = { 24 03 [2] 16 21 [2] 10 14 [2] 3e 14 [2] 01 08 }

  condition:
    any of them
}