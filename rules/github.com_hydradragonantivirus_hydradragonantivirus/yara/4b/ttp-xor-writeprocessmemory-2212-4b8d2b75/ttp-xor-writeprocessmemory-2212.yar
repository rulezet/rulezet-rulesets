rule TTP_XOR_WriteProcessMemory_2212 {
  strings:
    $key_2212 = { 75 60 [2] 47 42 [2] 41 77 [2] 6f 77 [2] 50 6b }

  condition:
    any of them
}