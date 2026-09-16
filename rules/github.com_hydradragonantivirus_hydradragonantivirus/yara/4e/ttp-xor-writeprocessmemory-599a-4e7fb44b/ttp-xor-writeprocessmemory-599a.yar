rule TTP_XOR_WriteProcessMemory_599a {
  strings:
    $key_599a = { 0e e8 [2] 3c ca [2] 3a ff [2] 14 ff [2] 2b e3 }

  condition:
    any of them
}