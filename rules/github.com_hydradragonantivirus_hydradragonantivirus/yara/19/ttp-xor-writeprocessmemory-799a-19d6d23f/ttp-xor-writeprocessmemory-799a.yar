rule TTP_XOR_WriteProcessMemory_799a {
  strings:
    $key_799a = { 2e e8 [2] 1c ca [2] 1a ff [2] 34 ff [2] 0b e3 }

  condition:
    any of them
}