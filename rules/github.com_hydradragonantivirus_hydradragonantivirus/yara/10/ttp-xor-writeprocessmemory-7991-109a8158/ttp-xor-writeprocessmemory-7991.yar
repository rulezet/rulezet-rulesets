rule TTP_XOR_WriteProcessMemory_7991 {
  strings:
    $key_7991 = { 2e e3 [2] 1c c1 [2] 1a f4 [2] 34 f4 [2] 0b e8 }

  condition:
    any of them
}