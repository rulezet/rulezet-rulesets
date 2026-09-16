rule TTP_XOR_WriteProcessMemory_7610 {
  strings:
    $key_7610 = { 21 62 [2] 13 40 [2] 15 75 [2] 3b 75 [2] 04 69 }

  condition:
    any of them
}