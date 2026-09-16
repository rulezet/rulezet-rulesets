rule TTP_XOR_WriteProcessMemory_0012 {
  strings:
    $key_0012 = { 57 60 [2] 65 42 [2] 63 77 [2] 4d 77 [2] 72 6b }

  condition:
    any of them
}