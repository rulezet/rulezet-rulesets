rule TTP_XOR_WriteProcessMemory_3c12 {
  strings:
    $key_3c12 = { 6b 60 [2] 59 42 [2] 5f 77 [2] 71 77 [2] 4e 6b }

  condition:
    any of them
}