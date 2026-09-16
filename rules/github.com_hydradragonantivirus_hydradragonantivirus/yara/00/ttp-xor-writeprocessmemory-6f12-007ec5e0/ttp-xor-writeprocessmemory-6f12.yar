rule TTP_XOR_WriteProcessMemory_6f12 {
  strings:
    $key_6f12 = { 38 60 [2] 0a 42 [2] 0c 77 [2] 22 77 [2] 1d 6b }

  condition:
    any of them
}