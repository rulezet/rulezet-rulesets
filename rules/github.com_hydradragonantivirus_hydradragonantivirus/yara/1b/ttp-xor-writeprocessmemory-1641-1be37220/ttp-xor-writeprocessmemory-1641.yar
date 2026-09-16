rule TTP_XOR_WriteProcessMemory_1641 {
  strings:
    $key_1641 = { 41 33 [2] 73 11 [2] 75 24 [2] 5b 24 [2] 64 38 }

  condition:
    any of them
}