rule TTP_XOR_WriteProcessMemory_0312 {
  strings:
    $key_0312 = { 54 60 [2] 66 42 [2] 60 77 [2] 4e 77 [2] 71 6b }

  condition:
    any of them
}