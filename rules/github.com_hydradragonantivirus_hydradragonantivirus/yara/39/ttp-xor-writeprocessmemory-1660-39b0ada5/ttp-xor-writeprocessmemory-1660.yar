rule TTP_XOR_WriteProcessMemory_1660 {
  strings:
    $key_1660 = { 41 12 [2] 73 30 [2] 75 05 [2] 5b 05 [2] 64 19 }

  condition:
    any of them
}