rule TTP_XOR_WriteProcessMemory_1612 {
  strings:
    $key_1612 = { 41 60 [2] 73 42 [2] 75 77 [2] 5b 77 [2] 64 6b }

  condition:
    any of them
}