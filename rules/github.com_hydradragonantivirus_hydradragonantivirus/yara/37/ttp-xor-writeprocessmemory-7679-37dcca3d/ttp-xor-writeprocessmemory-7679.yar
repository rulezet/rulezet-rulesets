rule TTP_XOR_WriteProcessMemory_7679 {
  strings:
    $key_7679 = { 21 0b [2] 13 29 [2] 15 1c [2] 3b 1c [2] 04 00 }

  condition:
    any of them
}