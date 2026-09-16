rule TTP_XOR_WriteProcessMemory_7119 {
  strings:
    $key_7119 = { 26 6b [2] 14 49 [2] 12 7c [2] 3c 7c [2] 03 60 }

  condition:
    any of them
}