rule TTP_XOR_WriteProcessMemory_7608 {
  strings:
    $key_7608 = { 21 7a [2] 13 58 [2] 15 6d [2] 3b 6d [2] 04 71 }

  condition:
    any of them
}