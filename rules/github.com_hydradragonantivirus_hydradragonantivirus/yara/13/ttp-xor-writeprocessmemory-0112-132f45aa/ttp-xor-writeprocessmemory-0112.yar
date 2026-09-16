rule TTP_XOR_WriteProcessMemory_0112 {
  strings:
    $key_0112 = { 56 60 [2] 64 42 [2] 62 77 [2] 4c 77 [2] 73 6b }

  condition:
    any of them
}