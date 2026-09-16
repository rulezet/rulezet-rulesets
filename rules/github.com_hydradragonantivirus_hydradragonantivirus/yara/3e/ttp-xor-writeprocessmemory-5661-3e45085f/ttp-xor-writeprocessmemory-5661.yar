rule TTP_XOR_WriteProcessMemory_5661 {
  strings:
    $key_5661 = { 01 13 [2] 33 31 [2] 35 04 [2] 1b 04 [2] 24 18 }

  condition:
    any of them
}