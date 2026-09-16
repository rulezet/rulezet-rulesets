rule TTP_XOR_WriteProcessMemory_2b12 {
  strings:
    $key_2b12 = { 7c 60 [2] 4e 42 [2] 48 77 [2] 66 77 [2] 59 6b }

  condition:
    any of them
}