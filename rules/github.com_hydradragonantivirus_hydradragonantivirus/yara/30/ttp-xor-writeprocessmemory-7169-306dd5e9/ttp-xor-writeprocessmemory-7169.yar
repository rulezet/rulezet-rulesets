rule TTP_XOR_WriteProcessMemory_7169 {
  strings:
    $key_7169 = { 26 1b [2] 14 39 [2] 12 0c [2] 3c 0c [2] 03 10 }

  condition:
    any of them
}